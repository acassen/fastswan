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
    """Symmetric IMIX combining the full ipsec-cx7-multi.py iMIX at every port.

    Each port emits both the clients and cmg sub-profiles for 4G and 5G
    in the same direction, so 4G and 5G coexist on the same injection
    point. The same aggregate runs in both directions to balance encrypt
    and decrypt CPU load across the two gateways.
    """

    ip_range: dict[str, IPRange] = {
        "cmg": IPRange(start="16.0.0.1", count=20),
        "clients": IPRange(start="48.0.0.1", count=500),
        "cmg1": IPRange(start="17.0.0.1", count=20),
        "clients1": IPRange(start="49.0.0.1", count=500),
    }

    # Lighter (clients) iMIX from ipsec-cx7-multi.py.
    profiles_clients: dict[str, list[StreamProperties]] = {
        "4g": [
            StreamProperties(size=114, pps=27991),
            StreamProperties(size=200, pps=5841),
            StreamProperties(size=491, pps=1807),
            StreamProperties(size=1000, pps=2488),
            StreamProperties(size=1428, pps=6039),
        ],
        "5g": [
            StreamProperties(size=113, pps=14171),
            StreamProperties(size=208, pps=3255),
            StreamProperties(size=477, pps=1135),
            StreamProperties(size=994, pps=2190),
            StreamProperties(size=1417, pps=4741),
        ],
    }

    # Heavier (cmg) iMIX from ipsec-cx7-multi.py.
    profiles_cmg: dict[str, list[StreamProperties]] = {
        "4g": [
            StreamProperties(size=120, pps=16960),
            StreamProperties(size=218, pps=9161),
            StreamProperties(size=438, pps=2960),
            StreamProperties(size=1075, pps=5619),
            StreamProperties(size=1398, pps=56458),
        ],
        "5g": [
            StreamProperties(size=112, pps=7703),
            StreamProperties(size=221, pps=3320),
            StreamProperties(size=437, pps=1527),
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

        # cmg keeps a per-port offset so ports 0/1 (and 2/3) use disjoint
        # source subsets for RSS spread. cmg does not select the tunnel,
        # so the offset is harmless on this side.
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

        # No offset on clients: both directions must hit the same /32 set
        # so each tunnel carries encrypt and decrypt (count == tunnels).
        clients_range = self.ip_range[clients_key]
        vm.var(
            name="clients_ip", size=4, op="inc",
            min_value=clients_range.start,
            max_value=str(
                netaddr.IPAddress(clients_range.start)
                + clients_range.count - (1 if clients_range.count else 0)
            ),
        )

        # Even port_id sends cmg -> clients (downstream), odd port_id
        # sends clients -> cmg (upstream). Same aggregate both ways
        # keeps the load symmetric.
        if port_id % 2 == 0:
            vm.write(fv_name="cmg_ip", pkt_offset="IP.src")
            vm.write(fv_name="clients_ip", pkt_offset="IP.dst")
        else:
            vm.write(fv_name="clients_ip", pkt_offset="IP.src")
            vm.write(fv_name="cmg_ip", pkt_offset="IP.dst")

        vm.fix_chksum()

        return [
            self.create_stream(port_id, properties, vm)
            for profiles in (self.profiles_clients, self.profiles_cmg)
            for _, sub_profile in profiles.items()
            for properties in sub_profile
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
