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
- [x] [xfrm: delete intermediate secpath entry in packet offload]
- [x] [net/mlx5e: Separate address related variables to be in struct]
- [x] [net/mlx5e: Properly match IPsec subnet addresses]
- [x] [xfrm: fix tunnel mode TX datapath in packet offload mode]
- [x] [net/mlx5e: Don't update neigh entries in IPsec ESN overlap]
- [x] [net/mlx5e: Support routed networks during IPsec accel MACs init]

  [xfrm: Support ESN context update to hardware for TX]: https://fastswan.org/kernel-patches/0000-xfrm-Support-ESN-context-update-to-hardware-for-TX.patch
  [net/mlx5e: Update TX ESN context for IPSec hardware offload]: https://fastswan.org/kernel-patches/0001-net-mlx5e-Update-TX-ESN-context-for-IPSec-hardware-o.patch
  [xfrm: delete intermediate secpath entry in packet offload]: https://fastswan.org/kernel-patches/0002-xfrm-delete-intermediate-secpath-entry-in-packet-off.patch
  [net/mlx5e: Separate address related variables to be in struct]: https://fastswan.org/kernel-patches/0008-net-mlx5e-Separate-address-related-variables-to-be-i.patch
  [net/mlx5e: Properly match IPsec subnet addresses]: https://fastswan.org/kernel-patches/0009-net-mlx5e-Properly-match-IPsec-subnet-addresses.patch
  [xfrm: fix tunnel mode TX datapath in packet offload mode]: https://fastswan.org/kernel-patches/0010-xfrm-fix-tunnel-mode-TX-datapath-in-packet-offload-m.patch
  [net/mlx5e: Don't update neigh entries in IPsec ESN overlap]: https://fastswan.org/kernel-patches/0010-net-mlx5e-Don-t-update-neigh-entries-in-IPsec-ESN-ov.patch
  [net/mlx5e: Support routed networks during IPsec accel MACs init]: https://fastswan.org/kernel-patches/0011-net-mlx5e-Support-routed-networks-during-IPsec-accel-MACs-init.patch

  [Linux Kernel 6.13]: https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.13.tar.xz
  [kernel/git/leon/linux-rdma.git ipsec-fixes branch]: https://git.kernel.org/pub/scm/linux/kernel/git/leon/linux-rdma.git/log/?h=ipsec-fixes

## strongSwan

Last stable strongSwan supporting hw_offload operations. At the time of writing, [strongSwan version 6.0.0] is a good choice.

  [strongSwan version 6.0.0]: https://strongswan.org/download.html
