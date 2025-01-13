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
device driver and the XFRM layer. At the time of writing, the Kernel version used is 6.13-rc1. However some dev iterations have been done with Nvidia R&D in late December
2024 in order to extend and fix Tunnel mode support in the mlx5 Driver. Produced patches
are being merged into the Kernel mainline, but if you want to try it in the meantime
then you will need to apply the patches below. These patches are included in the [kernel/git/leon/linux-rdma.git ipsec-fixes branch].

- [x] [xfrm: Support ESN context update to hardware for TX]
- [x] [net/mlx5e: Fix inversion dependency warning while enabling IPsec tunnel]
- [x] [net/mlx5e: Properly match IPsec subnet addresses]
- [x] [net/mlx5e: Rely on reqid in IPsec tunnel mode]
- [x] [net/mlx5e: Always start IPsec sequence number from 1]
- [x] [xfrm: delete intermediate secpath entry in packet offload mode]

  [xfrm: Support ESN context update to hardware for TX]: https://fastswan.org/kernel-patches/0001-xfrm-Support-ESN-context-update-to-hardware-for-TX.patch
  [net/mlx5e: Fix inversion dependency warning while enabling IPsec tunnel]: https://fastswan.org/kernel-patches/0002-net-mlx5e-Fix-inversion-dependency-warning-while-ena.patch
  [net/mlx5e: Properly match IPsec subnet addresses]: https://fastswan.org/kernel-patches/0003-net-mlx5e-Properly-match-IPsec-subnet-addresses.patch
  [net/mlx5e: Rely on reqid in IPsec tunnel mode]: https://fastswan.org/kernel-patches/0004-net-mlx5e-Rely-on-reqid-in-IPsec-tunnel-mode.patch
  [net/mlx5e: Always start IPsec sequence number from 1]: https://fastswan.org/kernel-patches/0005-net-mlx5e-Always-start-IPsec-sequence-number-from-1.patch
  [xfrm: delete intermediate secpath entry in packet offload mode]: https://fastswan.org/kernel-patches/0006-xfrm-delete-intermediate-secpath-entry-in-packet-off.patch

  [kernel/git/leon/linux-rdma.git ipsec-fixes branch]: https://git.kernel.org/pub/scm/linux/kernel/git/leon/linux-rdma.git/log/?h=ipsec-fixes

## strongSwan

Last stable strongSwan supporting hw_offload operations. At the time of writing, [strongSwan version 6.0.0] is a good choice.

  [strongSwan version 6.0.0]: https://strongswan.org/download.html
