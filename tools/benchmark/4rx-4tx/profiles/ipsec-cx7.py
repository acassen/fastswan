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
    """Symmetric IMIX targeting 20 Mpps / ~98 Gbps for IPsec gateway saturation.

    Per port: 5 Mpps at avg ~593 B/pkt (L2 plaintext).
    4 ports:  20 Mpps total, ~95 Gbps L2 / ~99 Gbps L1 plaintext.

    All sizes <= 1428 B so ESP-encrypted frames stay under MTU 1500
    (AES-GCM tunnel overhead is ~62 B).

    Run with -m 1 to hit nominal rates. Reduce -m to back off if TRex
    or the gateway can't keep up.
    """

    ip_range: dict[str, IPRange] = {
        "cmg":      IPRange(start="16.0.0.1", count=20),
        "clients":  IPRange(start="48.0.0.1", count=1024),
        "cmg1":     IPRange(start="17.0.0.1", count=20),
        "clients1": IPRange(start="49.0.0.1", count=1024),
    }

    # Six-bucket IMIX shaped to hit 5 Mpps at 593 B avg per port.
    profile: list[StreamProperties] = [
        StreamProperties(size=64,   pps=1300000),
        StreamProperties(size=128,  pps=800000),
        StreamProperties(size=256,  pps=600000),
        StreamProperties(size=512,  pps=500000),
        StreamProperties(size=1024, pps=500000),
        StreamProperties(size=1428, pps=1300000),
    ]

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
            for properties in self.profile
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
