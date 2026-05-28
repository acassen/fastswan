---
title: Interface block
---

# `interface` block

The `interface` block declares a network interface to fastSwan and
holds every per-port knob: BPF program binding, hairpin next-hop
pre-resolution, and the `flower-mode` (aka `furious-mode`)
hardware-offload keywords.

A typical entry:

```
interface p0
 bpf-program xdp-xfrm
 hairpin-to-nexthop 10.0.0.1
 flower-inbound-mode
 flower-outbound-mode
 flower-decrement-ttl
 no shutdown
```

## `interface STRING`

Declare or enter the configuration block of a network interface.
The kernel ifindex is resolved via `if_nametoindex()` the first time
the interface is referenced, and the entry is appended to the local
network interfaces DB.

```
fastSwan(config)# interface p0
fastSwan(config-if)#
```

### `no interface STRING`

Detach the BPF program currently attached (if any) and remove the
interface declaration.

## Inside the `interface` block

### `description LINE`

Free-form label stored alongside the interface. Informational,
surfaced by `config write`.

### `bpf-program STRING`

Bind a previously declared `bpf-program` to this interface. The
kernel attach (`bpf_program__attach_xdp` on the netdev ifindex)
only fires when the interface is brought up via `no shutdown`.

```
interface p0
 bpf-program xdp-xfrm
```

### `no bpf-program`

Detach and unbind whatever program is currently attached.

### `shutdown`

Detach the XDP link of the bound bpf-program from this interface
while keeping the binding, so a later `no shutdown` re-attaches the
same program.

### `no shutdown`

Bring the interface up by attaching the bound bpf-program in XDP
driver mode. Lazy-loads the BPF object if it is not running yet.

## Hairpin next-hop pre-resolution

### `hairpin-to-nexthop A.B.C.D`

Pre-resolve the next-hop MAC for inbound (post-IPsec-decap) traffic
on this interface and skip the per-packet `bpf_fib_lookup`. The
reformat is rebuilt automatically when the kernel ARP entry
changes; until first resolution, the BPF datapath falls back to
`bpf_fib_lookup`.

```
interface p0
 hairpin-to-nexthop 10.0.0.1
```

### `no hairpin-to-nexthop`

Drop the binding; inbound packets fall back to the regular
`fib_lookup` path.

## flower-mode (furious-mode) keywords

These keywords activate the hardware-offload forwarding model on
mlx5 NICs. Each one probes the device before enabling. If the
device or the kernel cannot offload the rule, fastSwan logs the
reason and the matching direction stays on XDP, so the same config
works across hardware generations.

### `flower-outbound-mode`

Replace the XDP egress path with mlx5 TC flower HW offload on this
interface. Outbound XFRM packet-mode policies are mirrored to
`clsact` ingress flower rules with `skip_sw` and a mirred-egress
redirect. The inbound direction stays on XDP unless
`flower-inbound-mode` is also enabled. mlx5 only.

### `no flower-outbound-mode`

Restore the XDP egress path on this interface and remove every
outbound flower filter installed by fastSwan.

### `flower-inbound-mode [chain <1-65535>]`

Replace the XDP inbound path with mlx5 TC flower HW offload on the
post-decrypt chain. Requires kernel post-decrypt placement support.
The optional `chain` keyword overrides the post-decrypt TC chain
index (default 1). The outbound direction stays on XDP unless
`flower-outbound-mode` is also enabled. mlx5 only.

```
interface p0
 flower-inbound-mode chain 3
```

### `no flower-inbound-mode`

Restore the XDP inbound path and remove every inbound flower
filter installed by fastSwan.

### `flower-decrement-ttl`

Prepend `pedit ex munge ip ttl dec` to every flower rule on this
interface, both directions. Default leaves the TTL untouched.

### `no flower-decrement-ttl`

Drop the TTL-decrement action from flower rules on this interface.
