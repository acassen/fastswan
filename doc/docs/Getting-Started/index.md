---
title: Prerequisites
---

# Getting Started

fastSwan relies on low-level features supported by NIC, Linux Kernel and strongSwan.

## NIC

During our implementation, Nvidia [ConnectX Cards]: ConnectX-6-Dx & ConnectX-7 were used with success.
This is currently the best choice to support HW offload for both Crypto mode and Packet mode (if this assertion is wrong, dont even hesitate to send HW for evaluation)

  [ConnectX Cards]: https://www.nvidia.com/fr-fr/networking/ethernet-adapters/

## Linux Kernel

A newer Linux Kernel is required that supports IPsec HW offload at both the network
device driver and the XFRM layer. However some dev iterations have been done with
Nvidia R&D in late December 2024 in order to extend and fix Tunnel mode support in
the mlx5 Driver. Produced patches are being merged into the Kernel mainline, but if
you want to try it in the meantime then you will need to apply the patches below against
[Linux Kernel 6.13].
These patches are included in the [kernel/git/leon/linux-rdma.git ipsec-fixes branch].

- [x] [xfrm: Support ESN context update to hardware for TX]
- [x] [net/mlx5e: Update TX ESN context for IPSec hardware offload]
- [x] [xfrm: delay initialization of offload path till its actually requested]
- [x] [xfrm: delete intermediate secpath entry in packet offload]
- [x] [xfrm: simplify SA initialization routine]
- [x] [xfrm: rely on XFRM offload]
- [x] [xfrm: provide common xdo_dev_offload_ok callback]
- [x] [bonding: delete always true device check]
- [x] [xfrm: check for PMTU in tunnel mode for packet offload]
- [x] [net/mlx5e: Separate address related variables to be in struct]
- [x] [net/mlx5e: Properly match IPsec subnet addresses]
- [x] [xfrm: fix tunnel mode TX datapath in packet offload mode]

  [xfrm: Support ESN context update to hardware for TX]: https://fastswan.org/kernel-patches/0000-xfrm-Support-ESN-context-update-to-hardware-for-TX.patch
  [net/mlx5e: Update TX ESN context for IPSec hardware offload]: https://fastswan.org/kernel-patches/0001-net-mlx5e-Update-TX-ESN-context-for-IPSec-hardware-o.patch
  [xfrm: delay initialization of offload path till its actually requested]: https://fastswan.org/kernel-patches/0002-xfrm-delay-initialization-of-offload-path-till-its-a.patch
  [xfrm: delete intermediate secpath entry in packet offload]: https://fastswan.org/kernel-patches/0002-xfrm-delete-intermediate-secpath-entry-in-packet-off.patch
  [xfrm: simplify SA initialization routine]: https://fastswan.org/kernel-patches/0003-xfrm-simplify-SA-initialization-routine.patch
  [xfrm: rely on XFRM offload]: https://fastswan.org/kernel-patches/0004-xfrm-rely-on-XFRM-offload.patch
  [xfrm: provide common xdo_dev_offload_ok callback]: https://fastswan.org/kernel-patches/0005-xfrm-provide-common-xdo_dev_offload_ok-callback-impl.patch
  [bonding: delete always true device check]: https://fastswan.org/kernel-patches/0006-bonding-delete-always-true-device-check.patch
  [xfrm: check for PMTU in tunnel mode for packet offload]: https://fastswan.org/kernel-patches/0007-xfrm-check-for-PMTU-in-tunnel-mode-for-packet-offloa.patch
  [net/mlx5e: Separate address related variables to be in struct]: https://fastswan.org/kernel-patches/0008-net-mlx5e-Separate-address-related-variables-to-be-i.patch
  [net/mlx5e: Properly match IPsec subnet addresses]: https://fastswan.org/kernel-patches/0009-net-mlx5e-Properly-match-IPsec-subnet-addresses.patch
  [xfrm: fix tunnel mode TX datapath in packet offload mode]: https://fastswan.org/kernel-patches/0010-xfrm-fix-tunnel-mode-TX-datapath-in-packet-offload-m.patch

  [Linux Kernel 6.13]: https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.13.tar.xz
  [kernel/git/leon/linux-rdma.git ipsec-fixes branch]: https://git.kernel.org/pub/scm/linux/kernel/git/leon/linux-rdma.git/log/?h=ipsec-fixes

## strongSwan

Last stable strongSwan supporting hw_offload operations. At the time of writing, [strongSwan version 6.0.0] is a good choice.

  [strongSwan version 6.0.0]: https://strongswan.org/download.html
