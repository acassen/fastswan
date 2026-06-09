import dataclasses
import netaddr
from trex.stl import api
from scapy.all import Ether, IP, UDP


@dataclasses.dataclass
class StreamProperties:
    pps: int
    size: int  # L2 size


@dataclasses.dataclass
class IPRange:
    start: str
    count: int


class STLIPsec:
    """Symmetric bidirectional IMIX profile for IPsec gateway testing.

    Mirror of ipsec-cx-multi.py with a single profile used in both
    directions so encrypt and decrypt CPU load are balanced across the
    two gateways. Both directions carry the same pps and the same
    packet-size mix.
    """

    ip_range: dict[str, IPRange] = {
        "cmg":      IPRange(start="16.0.0.1", count=20),
        "clients":  IPRange(start="48.0.0.1", count=60240),
        "cmg1":     IPRange(start="17.0.0.1", count=20),
        "clients1": IPRange(start="49.0.0.1", count=60240),
    }

    # Single 4G + 5G IMIX, used by every port for both directions.
    profile: dict[str, list[StreamProperties]] = {
        "4g": [
            StreamProperties(size=120,  pps=16960),
            StreamProperties(size=218,  pps=9161),
            StreamProperties(size=438,  pps=2960),
            StreamProperties(size=1075, pps=5619),
            StreamProperties(size=1398, pps=56458),
        ],
        "5g": [
            StreamProperties(size=112,  pps=7703),
            StreamProperties(size=221,  pps=3320),
            StreamProperties(size=437,  pps=1527),
            StreamProperties(size=1034, pps=3055),
            StreamProperties(size=1367, pps=55815),
        ],
    }

    def create_stream(self, port_id, properties: StreamProperties, vm):
        base_pkt = Ether() / IP() / UDP(sport=6000 + port_id, dport=7000 + port_id)
        pad = max(0, properties.size - len(base_pkt)) * "x"
        pkt = api.STLPktBuilder(pkt=base_pkt / pad, vm=vm)
        return api.STLStream(packet=pkt, mode=api.STLTXCont(pps=properties.pps))

    def get_streams(self, port_id, **kwargs):
        vm = api.STLVM()

        if port_id == 0 or port_id == 1:
            cmg_key, clients_key = "cmg", "clients"
        else:
            cmg_key, clients_key = "cmg1", "clients1"

        # Paired-port offset keeps source IP subsets disjoint between
        # ports 0/1 (and 2/3) so RSS spreads them differently.
        pair_index = port_id % 2

        cmg_range = self.ip_range[cmg_key]
        cmg_offset = cmg_range.count * pair_index
        vm.var(
            name="cmg_ip", size=4, op="inc",
            min_value=str(netaddr.IPAddress(cmg_range.start) + cmg_offset),
            max_value=str(
                netaddr.IPAddress(cmg_range.start) + cmg_offset
                + cmg_range.count - (1 if cmg_range.count else 0)
            ),
        )

        clients_range = self.ip_range[clients_key]
        clients_offset = clients_range.count * pair_index
        vm.var(
            name="clients_ip", size=4, op="inc",
            min_value=str(netaddr.IPAddress(clients_range.start) + clients_offset),
            max_value=str(
                netaddr.IPAddress(clients_range.start) + clients_offset
                + clients_range.count - (1 if clients_range.count else 0)
            ),
        )

        # Even port_id = cmg -> clients (downstream).
        # Odd  port_id = clients -> cmg (upstream).
        # Same profile both ways keeps the load symmetric.
        if port_id % 2 == 0:
            vm.write(fv_name="cmg_ip", pkt_offset="IP.src")
            vm.write(fv_name="clients_ip", pkt_offset="IP.dst")
        else:
            vm.write(fv_name="clients_ip", pkt_offset="IP.src")
            vm.write(fv_name="cmg_ip", pkt_offset="IP.dst")

        vm.fix_chksum()

        return [
            self.create_stream(port_id, properties, vm)
            for _, p in self.profile.items()
            for properties in p
        ] + [
            api.STLStream(
                packet=api.STLPktBuilder(
                    pkt=Ether() / IP() / UDP(sport=1025, dport=9) / ("!" * 700), vm=vm
                ),
                mode=api.STLTXCont(pps=100),
                flow_stats=api.STLFlowLatencyStats(port_id),
            )
        ]


def register():
    return STLIPsec()
