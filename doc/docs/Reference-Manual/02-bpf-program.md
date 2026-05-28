---
title: bpf-program block
---

# `bpf-program` block

The `bpf-program` block declares a named eBPF object that fastSwan
can attach to one or several interfaces. Programs are stored as
`struct fswan_bpf_prog` in `daemon_data->bpf_progs` and carry the
filesystem path, an optional section name, and a lifecycle flag.

A program declaration is independent of any interface; bringing the
program up (`no shutdown`) only loads the object into the kernel.
The actual XDP attach happens when an `interface` block referencing
this program is itself brought up.

```
bpf-program xdp-xfrm
 description Main XDP/XFRM offload program
 path /etc/fastswan/xfrm_offload.bpf
 no shutdown
```

## `bpf-program STRING`

Declare or enter the configuration block of a named BPF program.
`STRING` is the symbolic name referenced later from `interface`
blocks.

```
fastSwan(config)# bpf-program xdp-xfrm
fastSwan(config-bpf)#
```

### `no bpf-program STRING`

Detach every interface using this program, unload the BPF object,
then drop the declaration.

## Inside the `bpf-program` block

### `description LINE`

Free-form label stored alongside the BPF program. Purely
informational, surfaced by `config write` and the show commands.

### `path STRING`

Absolute filesystem path of the compiled `.bpf` object that
libbpf will open when this program is brought up (`no shutdown`).

```
bpf-program xdp-xfrm
 path /etc/fastswan/xfrm_offload.bpf
```

### `prog-name STRING`

Override the BPF section/function name to attach when the object
contains several programs. Defaults to the first XDP program found.

```
bpf-program xdp-xfrm
 path /etc/fastswan/xfrm_offload.bpf
 prog-name xfrm_offload
```

### `shutdown`

Detach every interface bound to this program and unload the BPF
object from the kernel. The declaration itself is preserved, so a
later `no shutdown` re-loads the same object.

### `no shutdown`

Open the `.bpf` object set by `path`, run the kernel verifier and
wire the XFRM offload maps. Required before any interface can
attach to this program.
