---
title: Reference Manual
---

# Reference Manual

This section lists every fastSwan VTY command extracted from the
running source tree. The shell uses standard line-oriented VTY
conventions:

* `STRING`, `WORD`, `LINE` are free-form text tokens
* `A.B.C.D` and `X:X::X:X` denote an IPv4 and IPv6 address
* `A.B.C.D/M` is an IPv4 prefix
* `<low-high>` is an integer range
* `[xxx]` is optional, `(a|b|c)` is a mandatory choice
* `no <command>` reverses a configuration command, where supported

The manual is split by feature area.

* [Global configuration](01-global-config.md): hostname, CPU pinning,
  scheduling, memory lock, XFRM policy bootstrap, XDP stats toggle.
* [bpf-program block](02-bpf-program.md): declaring and loading the
  XDP/eBPF objects fastSwan attaches to interfaces.
* [Interface block](03-interface.md): per-interface configuration,
  including the new `flower-mode` (aka `furious-mode`) hardware
  offload keywords.
* [Show commands](04-show-commands.md): operational visibility over
  IPsec SAs and policies, interfaces, system CPU, BPF/XDP state.
* [Monitor & debug commands](05-monitor-debug.md): live refreshing
  dashboards and BPF debug tools.

## Connecting to the VTY

The default config exposes the VTY on a unix socket:

```
line vty
 no login
 listen unix owner fswan group fswan
```

The simplest way in is the built-in CLI client shipped with the
daemon:

```
$ fastswan --cli

 Welcome to fastSwan VTY

fastSwan>
```

A TCP listener works the same way (`listen 127.0.0.1 1664`),
reachable through `telnet` or `nc`. Two main modes are available
once connected:

* `enable` enters privileged mode (prompt becomes `fastSwan#`)
* `configure terminal` enters configuration mode (prompt
  becomes `fastSwan(config)#`)
* `?` lists every command available in the current mode
* `Ctrl-Z` or `end` leaves configuration mode
* `exit` closes the VTY session

Every operational command lives under `show`, `monitor` or `debug`
in the top-level or enable mode. Every configuration command lives
inside `configure terminal`, sometimes nested under a `bpf-program`
or `interface` block.
