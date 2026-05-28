---
title: Global configuration
---

# Global configuration

These commands sit at the top-level of `configure terminal` and
affect the whole daemon.

## `hostname WORD`

Sets the prompt label shown by the VTY (also written to the
configuration file). Inherited from the underlying VTY library.

## CPU pinning and scheduling

fastSwan separates three CPU concerns: which CPUs the daemon main
loop can run on, which CPUs the monitor pthread can run on, and which
CPUs are sampled for the dashboards. Each one has its own keyword,
and `no <keyword>` reverts it to default.

### `cpu-mask CPULIST`

Restrict daemon CPU monitoring and sampling to a subset of system
CPUs. `CPULIST` is a cpuset-format list, like `0-3,5,7-9`. Useful
when only a subset of CPUs runs dataplane work and the others should
not pollute the dashboards.

```
fastSwan(config)# cpu-mask 0-23
fastSwan(config)# no cpu-mask     ! revert to all CPUs
```

### `daemon-cpu CPULIST`

Pin the daemon main thread to a CPU set. The monitor pthread
inherits this affinity unless overridden via `monitor-cpu`.

```
fastSwan(config)# daemon-cpu 2-3
fastSwan(config)# no daemon-cpu
```

### `monitor-cpu CPULIST`

Pin the monitor pthread to its own CPU set. Useful when the monitor
should not share cycles with the daemon main loop. `no monitor-cpu`
falls back to the `daemon-cpu` set if configured.

### `daemon-priority <1-99>`

Set the daemon main thread to `SCHED_RR` with the given priority.
The monitor pthread inherits this priority unless overridden via
`monitor-priority`. `no daemon-priority` resets the thread to
`SCHED_OTHER`.

```
fastSwan(config)# daemon-priority 50
```

### `monitor-priority <1-99>`

Set the monitor pthread to `SCHED_RR` with the given priority.
`no monitor-priority` falls back to `daemon-priority`.

### `lock-memory`

Lock daemon pages in RAM via `mlockall()`, preventing swap-induced
latency spikes on the data path. `no lock-memory` releases the lock.

## XFRM bootstrap

### `load-existing-xfrm-policy`

Bootstrap the XDP fast path by mirroring all currently installed
kernel XFRM policies into the BPF LPM map. The daemon issues an
`XFRM_MSG_GETPOLICY` netlink dump and inserts each policy, so the
BPF data plane catches existing tunnels installed by strongSwan
before fastSwan started.

Typically placed at the end of the startup config:

```
load-existing-xfrm-policy
```

## XDP statistics toggle

### `disable-xdp-xfrm-offload-statistics`

Disable per-policy packet/byte counter accounting in the XDP fast
path. Reduces per-packet overhead at the cost of losing the
counters surfaced by `show xdp xfrm offload ...`.

### `no disable-xdp-xfrm-offload-statistics`

Re-enable per-policy packet/byte counter accounting (default).
