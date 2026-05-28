---
title: Monitor & debug
---

# Monitor and debug commands

`monitor` refreshes a live view at a chosen interval (1-60 seconds);
the screen redraws in place until you press Ctrl-C. `debug`
commands stream kernel-side diagnostic output.

## CPU monitors

### `monitor <1-60> system cpu`

Per-core CPU utilization refreshing every N seconds.

### `monitor <1-60> system cpu (ascii|block|braille|thin|dot|block-graph|braille-graph)`

Same view with an explicit rendering style:

* `ascii`: ASCII bar gauge
* `block`: solid block gauge with color
* `braille`: braille filled bar with color
* `thin`: thin line bar gauge with color
* `dot`: dot bar gauge with color
* `block-graph`: scrolling block graph with color
* `braille-graph`: braille dot graph with color

The graph styles keep a time history per CPU, while the gauge
styles show the current instantaneous load.

### `monitor <1-60> system cpu matrix`

2D grid layout of per-core CPU utilization. Good for high core
counts where the per-line layout no longer fits.

### `monitor <1-60> system cpu matrix (ascii|block|braille|thin|dot)`

Same with explicit gauge style.

## Interface monitors

### `monitor <1-60> interface WORD`

Refresh of `show interface dashboard` at the chosen interval.

### `monitor <1-60> interface ipsec WORD`

Refresh of `show interface ipsec` at the chosen interval.

## Debug

### `debug xdp bpf trace-pipe`

Stream `bpf_printk()` output from the kernel trace pipe. Useful for
diagnosing the XDP/BPF data path. Ctrl-C exits the stream.

```
fastSwan# debug xdp bpf trace-pipe
            <idle>-0       [004] ..s2.   123.456: bpf_trace_printk: xfrm hit ...
```
