---
title: Show commands
---

# Show commands

Operational visibility lives under `show`. The commands fall into
five groups: IPsec SAs/policies (kernel ground truth), interfaces,
BPF/XDP fast-path mirror state, and system CPU.

## IPsec

The IPsec show commands all rely on netlink `XFRM_MSG_GETSA` and
`XFRM_MSG_GETPOLICY`, so they reflect kernel ground truth. Only
packet-offload entries are surfaced.

### `show ipsec`

Combined SA + attached-policy operator view. Each SA is rendered
with its bound policies and the OFFLOAD path (`flower-packet (hw)`
for HW-offloaded directions, `xdp-packet` for XDP-handled ones).

```
fastSwan> show ipsec
[SA]  src 123.1.0.1 -> dst 123.3.1.5   esp spi 0xc3c13d31 reqid 8 mode tunnel
      offload packet dev p1 dir out    aead rfc4106(gcm(aes)) 288 bits
      ESP    pkts:34970634     bytes:35952311661    lastused never
      policies:
        dir out   17.0.0.0/8 -> 49.0.3.0/24   prio 383615 ptype main   flower-packet (hw)
            CLEAR (flower): pkts:6669618 bytes:7083559353
```

### `show ipsec summary`

One-shot count + cumulative-counters overview.

### `show ipsec stats`

Global SNMP counters from `/proc/net/xfrm_stat` (kernel-wide).

### `show ipsec sa`

Tabular view of Security Associations.

```
fastSwan> show ipsec sa
┏━━━━━━━━━━━┯━━━━━━━━━━━┯━━━━━━━┯━━━━━━━━━━━━┯━━━━━━━┯━━━━━━━━┯━━━━━┯━━━━━┯━━━━━━━━━━━━┯━━━━━━━━━┓
┃    SRC    │    DST    │ PROTO │    SPI     │ REQID │  MODE  │ DEV │ DIR │    PKTS    │  BYTES  ┃
┣━━━━━━━━━━━┿━━━━━━━━━━━┿━━━━━━━┿━━━━━━━━━━━━┿━━━━━━━┿━━━━━━━━┿━━━━━┿━━━━━┿━━━━━━━━━━━━┿━━━━━━━━━┫
┃ 123.1.0.1 │ 123.3.1.6 │  esp  │ 0xc80cc5c7 │  10   │ tunnel │ p1  │ out │          0 │       0 ┃
┃ 123.3.1.6 │ 123.1.0.1 │  esp  │ 0xc7e90f8d │  10   │ tunnel │ p1  │ in  │  444030305 │  152.6G ┃
┃ 123.1.0.1 │ 123.3.1.5 │  esp  │ 0xc3c13d31 │   8   │ tunnel │ p1  │ out │   34970634 │   33.5G ┃
┃ 123.3.1.5 │ 123.1.0.1 │  esp  │ 0xca53d3d1 │   8   │ tunnel │ p1  │ in  │  813911083 │  279.8G ┃
┗━━━━━━━━━━━┷━━━━━━━━━━━┷━━━━━━━┷━━━━━━━━━━━━┷━━━━━━━┷━━━━━━━━┷━━━━━┷━━━━━┷━━━━━━━━━━━━┷━━━━━━━━━┛
```

### `show ipsec sa A.B.C.D`

Filter SAs by peer IPv4 (matches src or dst).

### `show ipsec sa X:X::X:X`

Filter SAs by peer IPv6 (matches src or dst).

### `show ipsec sa A.B.C.D A.B.C.D` / `... keys`

Source and destination IPv4 pair, multi-line iproute2-style detail.
The `keys` suffix reveals AEAD key bytes in hex (sensitive, avoid
logging this output).

### `show ipsec sa X:X::X:X X:X::X:X`

Same as above for IPv6.

### `show ipsec sa spi WORD` / `... keys`

Filter by SPI (`0xHEX`, hex or decimal accepted), multi-line
iproute2-style detail. The `keys` suffix reveals AEAD key bytes.

```
fastSwan> show ipsec sa spi 0xc7e90f8d
src 123.3.1.6 dst 123.1.0.1
	proto esp spi 0xc7e90f8d reqid 10 mode tunnel
	replay-window 0 flag af-unspec,esn
	aead rfc4106(gcm(aes)) <288 bits>
	lifetime current: 444030305 (packets), 163876268420 (bytes)
	lastused never
	hw stats: integrity-failed 0, replay-drop 0
	crypto offload parameters: dev p1 dir in mode packet
```

### `show ipsec sa interface WORD`

Filter SAs by their offload interface. The interface is resolved
through `if_nametoindex` and is not limited to fastSwan-managed
interfaces.

### `show ipsec policy`

Tabular view of XFRM policies. The `OFFLOAD` column shows the
forwarding path for each direction: `flower-packet (hw)` for
HW-offloaded entries and `xdp-packet` for XDP-handled ones.

```
fastSwan> show ipsec policy
┏━━━━━━━━━━━━━┯━━━━━━━━━━━━━┯━━━━━┯━━━━━━━━┯━━━━━┯━━━━━━━━━━━━━━━━━━━━┯━━━━━━━┯━━━━━━━━━━━┯━━━━━━━━┓
┃     SRC     │     DST     │ DIR │  PRIO  │ DEV │      OFFLOAD       │ REQID │   PKTS    │ BYTES  ┃
┣━━━━━━━━━━━━━┿━━━━━━━━━━━━━┿━━━━━┿━━━━━━━━┿━━━━━┿━━━━━━━━━━━━━━━━━━━━┿━━━━━━━┿━━━━━━━━━━━┿━━━━━━━━┫
┃ 17.0.0.0/8  │ 49.0.1.0/24 │ out │ 383615 │ p1  │ flower-packet (hw) │   4   │ 323452455 │ 319.9G ┃
┃ 49.0.1.0/24 │ 17.0.0.0/8  │ in  │ 383615 │ p1  │ flower-packet (hw) │   4   │ 576992762 │ 218.7G ┃
┃ 16.0.0.0/8  │ 48.0.1.0/24 │ out │ 383615 │ p0  │ flower-packet (hw) │   3   │ 323425276 │ 319.9G ┃
┃ 48.0.1.0/24 │ 16.0.0.0/8  │ in  │ 383615 │ p0  │ flower-packet (hw) │   3   │ 577055170 │ 218.8G ┃
┗━━━━━━━━━━━━━┷━━━━━━━━━━━━━┷━━━━━┷━━━━━━━━┷━━━━━┷━━━━━━━━━━━━━━━━━━━━┷━━━━━━━┷━━━━━━━━━━━┷━━━━━━━━┛
```

### `show ipsec policy detail`

Multi-line iproute2-style detail.

### `show ipsec policy A.B.C.D/M A.B.C.D/M`

Filter by source and destination IPv4 prefix.

### `show ipsec policy interface WORD`

Filter policies by their offload interface.

## Interface

### `show interface [STRING]`

Dump declared interfaces; with a name, dump that interface only.

### `show interface statistics`

Cumulative ethtool PHY counters and current rates for every
declared interface.

### `show interface statistics WORD`

Per-interface ethtool PHY counters, derived rates and per-queue
stats with the CPU each queue's IRQ is pinned to.

```
fastSwan> show interface statistics p0
Interface p0
  PHY counters:
    rx_packets:              10524040841     tx_packets:              9968491273
    rx_bytes:                6627721552798   tx_bytes:                6074088825326
    rx_discards:             0               tx_discards:             0
    tx_errors:               0
  Bandwidth: rx:373bps  tx:682bps  |  PPS: rx:0pps  tx:0pps
  IPsec offload counters:
    rx_pkts:                 7160558597      tx_pkts:                 2780695198
    rx_bytes:                2897080566278   tx_bytes:                3095923747424
    rx_drop_pkts:            0               tx_drop_pkts:            0
    rx_drop_bytes:           0               tx_drop_bytes:           0
  Bandwidth: rx:0bps  tx:0bps  |  PPS: rx:0pps  tx:0pps
  Per-queue counters:
      q   cpu      rx_packets        rx_bytes   rx_xdp_drop      tx_packets        tx_bytes
      0     4         2739034      1230470248             0         2921303      1303818523
      1     5         2553390      1169315218             0         2701804      1197307101
      ...
      9    13         2667248      1226014002             0         2387232      1120991005
```

### `show interface stats-csv WORD`

Emit one TSV row with the current rates and per-RX-queue CPU load,
intended for an external bench harness that loops every N seconds
and appends to a file. Columns: `ts_ns`, `ifname`, `rx_bps`,
`tx_bps`, `rx_pps`, `tx_pps`, then `(cpu, load)` pairs for each
bound RX queue.

### `show interface dashboard WORD`

Live activity dashboard for one interface. Renders stacked
rx/tx bandwidth and pps graphs over the rate-history ring, plus
per-RX-queue CPU-load gauges for the CPU pinned to each queue's
IRQ.

### `show interface ipsec WORD`

IPsec offload activity view for one interface: stacked rx/tx
bandwidth and pps graphs over the IPsec rate-history ring.

### `show interface rx-queue topology`

RX queue IRQ affinity grouped by NUMA node, plus a diagnostic of
single-CPU pinning and per-CPU uniqueness.

```
fastSwan> show interface rx-queue topology
 NUMA node 0  [cpus: 0-23  24 CPUs]
   p0  rx_queues:10
     rx-0   irq:169    cpu:4
     ...
Diagnostic:
  [ OK ] p0: pinning and NUMA locality correct
```

### `show interface topology`

Every PCI ethernet adapter on the host grouped by NUMA node,
showing BDF, vendor:device ID and bound driver.

```
fastSwan> show interface topology
PCI ethernet topology
├── NUMA node 0
│   ├── 0000:31:00.0
│   │   ├── vendor: Mellanox Technologies [15b3]
│   │   ├── model:  MT2910 Family [ConnectX-7] [1021]
│   │   ├── driver: mlx5_core
│   │   └── net:    p0
│   └── 0000:31:00.1
│       ├── vendor: Mellanox Technologies [15b3]
│       ├── model:  MT2910 Family [ConnectX-7] [1021]
│       ├── driver: mlx5_core
│       └── net:    p1
└── NUMA node 1
    ├── 0000:b1:00.0
    │   ├── vendor: Mellanox Technologies [15b3]
    │   ├── model:  MT2910 Family [ConnectX-7] [1021]
    │   ├── driver: mlx5_core
    │   └── net:    p2
    └── 0000:b1:00.1
        ├── vendor: Mellanox Technologies [15b3]
        ├── model:  MT2910 Family [ConnectX-7] [1021]
        ├── driver: mlx5_core
        └── net:    p3
```

## System

### `show system cpu`

Per-core CPU utilization snapshot.

## BPF / XDP

### `show xdp xfrm offload policy`

BPF/XDP fast-path mirror state with per-program clear-text
counters. Use to compare against `show ipsec policy` when
troubleshooting fast-path divergence (IPv4-only, packet-offload
only). Also the source for the `CLEAR` line in `show ipsec`.
