---
title: Installation
---

# Installation

## Dependencies

On Ubuntu the build needs libelf, zlib, llvm/clang for the eBPF
side, and meson/ninja for the build itself:

```
$ sudo apt install libelf-dev zlib1g-dev
$ sudo apt install llvm clang
$ sudo apt install meson ninja-build pkg-config
```

## Build

fastSwan now builds with meson. Clone the tree with its submodules
(libbpf is pulled as a wrap subproject) and run meson:

```
git clone --recursive git@github.com:acassen/fastswan.git
cd fastswan
meson setup builddir
meson compile -C builddir
```

The build produces the daemon and the companion eBPF object:

```
$ ls builddir/fastswan builddir/src/bpf/xfrm_offload.bpf
builddir/fastswan
builddir/src/bpf/xfrm_offload.bpf
```

## Configuration file

The configuration model has two independent blocks. `bpf-program`
declares an eBPF object and is referenced per `interface` block.
`interface` enables the XDP fast path and, when supported, the new
`flower-mode` (aka `furious-mode`) that pushes the forwarding work
into the NIC through tc flower.

```
$ cat /etc/fastswan/fastswan.conf
!
! fastSwan configuration saved from vty
!
hostname fastSwan
!
daemon-cpu 2-3
daemon-priority 50
lock-memory
cpu-mask 0-23
!
bpf-program xdp-xfrm
 path /etc/fastswan/xfrm_offload.bpf
 no shutdown
!
interface p0
 bpf-program xdp-xfrm
 route-to-nexthop 10.0.0.1
 flower-inbound-mode
 flower-outbound-mode
 flower-decrement-ttl
 no shutdown
!
interface p0.502
 no shutdown
!
interface p1
 bpf-program xdp-xfrm
 route-to-nexthop 10.1.0.1
 flower-inbound-mode
 flower-outbound-mode
 flower-decrement-ttl
 no shutdown
!
interface p1.504
 no shutdown
!
load-existing-xfrm-policy
!
line vty
 no login
 listen unix owner fswan group fswan
!
```

The flower-related keywords are optional and probe the NIC before
they activate. If the device or the kernel cannot offload the rule,
fastSwan falls back to XDP for that direction and logs the reason,
so the same config works across hardware generations.

* `flower-outbound-mode` lifts the encrypt direction into the NIC.
* `flower-inbound-mode` lifts the decrypt direction (needs the
  post-decrypt mlx5 patches).
* `flower-decrement-ttl` keeps the TTL decrement in HW through
  `pedit ttl dec`.
* `route-to-nexthop` resolves the LAN-side next hop once at warmup,
  so the fast path skips the kernel FIB lookup.
* `daemon-cpu`, `daemon-priority`, `lock-memory` and `cpu-mask` pin
  the control plane out of the isolated dataplane CPUs.

## Run & VTY

Start the daemon either with the SysV/systemd unit or by hand:

```
$ sudo builddir/fastswan --help
fastswan v1.x.y
Copyright (C) 2026 Alexandre Cassen, <acassen@gmail.com>
libbpf v1.6

Usage:
  fastswan
  fastswan -n
  fastswan -f fastswan.conf
  fastswan -d
  fastswan -h
  fastswan -v

$ sudo builddir/fastswan --dont-fork --log-console --log-detail \
        -f /etc/fastswan/fastswan.conf
```

The VTY listens on a unix socket by default. The daemon ships its
own CLI client, just run:

```
$ fastswan --cli

 Welcome to fastSwan VTY

fastSwan>
```

### Interface topology

`show interface topology` walks `/sys/bus/pci/devices` and prints
the PCI tree with NUMA locality, driver and netdev name, so the
bench layout is obvious at a glance:

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

### RX queue affinity

`show interface rx-queue topology` reports each RX queue, its IRQ
and the CPU it is pinned on, plus a diagnostic summary that flags
NUMA misalignment or shared CPUs:

```
fastSwan> show interface rx-queue topology
 NUMA node 0  [cpus: 0-23  24 CPUs]
   p0  rx_queues:10
     rx-0   irq:169    cpu:4
     rx-1   irq:176    cpu:5
     ...
     rx-9   irq:184    cpu:13
   p1  rx_queues:10
     rx-0   irq:171    cpu:14
     ...
     rx-9   irq:231    cpu:23

Diagnostic:
  [ OK ] p0: pinning and NUMA locality correct
  [ OK ] p1: pinning and NUMA locality correct
  [ OK ] all rx queue IRQs use distinct CPUs

  Overall: rx queue affinity configuration is optimal
```

### Interface statistics

`show interface statistics <iface>` aggregates PHY, IPsec-offload
and per-queue counters in one view:

```
fastSwan> show interface statistics p0
Interface p0
  PHY counters:
    rx_packets:              10524040841     tx_packets:              9968491273
    rx_bytes:                6627721552798   tx_bytes:                6074088825326
    rx_discards:             0               tx_discards:             0
  Bandwidth: rx:373bps  tx:682bps  |  PPS: rx:0pps  tx:0pps
  IPsec offload counters:
    rx_pkts:                 7160558597      tx_pkts:                 2780695198
    rx_bytes:                2897080566278   tx_bytes:                3095923747424
  Per-queue counters:
      q   cpu      rx_packets        rx_bytes      tx_packets        tx_bytes
      0     4         2739034      1230470248         2921303      1303818523
      1     5         2553390      1169315218         2701804      1197307101
      ...
```

### IPsec policies and SAs

`show ipsec` is the ground-truth view that walks kernel XFRM and
joins each SA with its bound policies and per-direction counters.
The `OFFLOAD` column shows which path carries the flow:
`flower-packet (hw)` for HW-offloaded directions and `xdp-packet`
for XDP-handled ones.

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

fastSwan> show ipsec sa
┏━━━━━━━━━━━┯━━━━━━━━━━━┯━━━━━━━┯━━━━━━━━━━━━┯━━━━━━━┯━━━━━━━━┯━━━━━┯━━━━━┯━━━━━━━━━━━━┯━━━━━━━━━┓
┃    SRC    │    DST    │ PROTO │    SPI     │ REQID │  MODE  │ DEV │ DIR │    PKTS    │  BYTES  ┃
┣━━━━━━━━━━━┿━━━━━━━━━━━┿━━━━━━━┿━━━━━━━━━━━━┿━━━━━━━┿━━━━━━━━┿━━━━━┿━━━━━┿━━━━━━━━━━━━┿━━━━━━━━━┫
┃ 123.1.0.1 │ 123.3.1.5 │  esp  │ 0xc3c13d31 │   8   │ tunnel │ p1  │ out │   34970634 │   33.5G ┃
┃ 123.3.1.5 │ 123.1.0.1 │  esp  │ 0xca53d3d1 │   8   │ tunnel │ p1  │ in  │  813911083 │  279.8G ┃
┗━━━━━━━━━━━┷━━━━━━━━━━━┷━━━━━━━┷━━━━━━━━━━━━┷━━━━━━━┷━━━━━━━━┷━━━━━┷━━━━━┷━━━━━━━━━━━━┷━━━━━━━━━┛
```

`show ipsec` joins both views into a single tree per SA, including
the policies, the OFFLOAD path and the CLEAR-side flower or XDP
counter for each direction:

```
fastSwan> show ipsec
[SA]  src 123.1.0.1 -> dst 123.3.1.5   esp spi 0xc3c13d31 reqid 8 mode tunnel
      offload packet dev p1 dir out    aead rfc4106(gcm(aes)) 288 bits
      ESP    pkts:34970634     bytes:35952311661    lastused never
      policies:
        dir out   17.0.0.0/8 -> 49.0.3.0/24   prio 383615 ptype main   flower-packet (hw)
            CLEAR (flower): pkts:6669618 bytes:7083559353
...
```
