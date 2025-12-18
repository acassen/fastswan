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
the mlx5 Driver. Produced patches has been merged into the Linux Kernel mainline,
a list of merged patches on this work can be found below.
More patches on on-going work can be found in the [kernel/git/leon/linux-rdma.git ipsec-fixes branch].

- [x] [xfrm: Support ESN context update to hardware for TX]
- [x] [xfrm: delete intermediate secpath entry in packet offload]
- [x] [xfrm: prevent high SEQ input in non-ESN mode]
- [x] [xfrm: simplify SA initialization routine]
- [x] [xfrm: rely on XFRM offload]
- [x] [xfrm: provide common xdo_dev_offload_ok callback]
- [x] [xfrm: check for PMTU in tunnel mode for packet offload]
- [x] [xfrm: fix tunnel mode TX datapath in packet offload mode]
- [x] [xfrm: validate assignment of maximal possible SEQ number]
- [x] [xfrm: prevent configuration of interface index when offload is used]
- [x] [xfrm: always initialize offload path]
- [x] [xfrm: fix offloading of cross-family tunnels]
- [x] [net/mlx5e: Update TX ESN context for IPSec hardware offload]
- [x] [net/mlx5e: Fix inversion dependency warning while enabling IPsec tunnel]
- [x] [net/mlx5e: Rely on reqid in IPsec tunnel mode]
- [x] [net/mlx5e: Always start IPsec sequence number from 1]
- [x] [net/mlx5e: Separate address related variables to be in struct]
- [x] [net/mlx5e: Properly match IPsec subnet addresses]
- [x] [net/mlx5e: Support routed networks during IPsec MACs initialization]
- [x] [net/mlx5e: Use ip6_dst_lookup instead of ipv6_dst_lookup_flow for MAC init]
- [x] [net/mlx5e: Trigger neighbor resolution for unresolved destinations]
- [x] [net/mlx5e: Prevent tunnel reformat when tunnel mode not allowed]

  [xfrm: Support ESN context update to hardware for TX]: https://fastswan.org/kernel-patches/0000-xfrm-Support-ESN-context-update-to-hardware-for-TX.patch
  [xfrm: delete intermediate secpath entry in packet offload]: https://fastswan.org/kernel-patches/0001-xfrm-delete-intermediate-secpath-entry-in-packet-off.patch
  [xfrm: prevent high SEQ input in non-ESN mode]: https://fastswan.org/kernel-patches/0001-xfrm-prevent-high-SEQ-input-in-non-ESN-mode.patch
  [xfrm: simplify SA initialization routine]: https://fastswan.org/kernel-patches/0002-xfrm-simplify-SA-initialization-routine.patch
  [xfrm: rely on XFRM offload]: https://fastswan.org/kernel-patches/0003-xfrm-rely-on-XFRM-offload.patch
  [xfrm: provide common xdo_dev_offload_ok callback]: https://fastswan.org/kernel-patches/0004-xfrm-provide-common-xdo_dev_offload_ok-callback-impl.patch
  [xfrm: check for PMTU in tunnel mode for packet offload]: https://fastswan.org/kernel-patches/0005-xfrm-check-for-PMTU-in-tunnel-mode-for-packet-offloa.patch
  [xfrm: fix tunnel mode TX datapath in packet offload mode]: https://fastswan.org/kernel-patches/0006-xfrm-fix-tunnel-mode-TX-datapath-in-packet-offload-m.patch
  [xfrm: validate assignment of maximal possible SEQ number]: https://fastswan.org/kernel-patches/0007-xfrm-validate-assignment-of-maximal-possible-SEQ-num.patch
  [xfrm: prevent configuration of interface index when offload is used]: https://fastswan.org/kernel-patches/0008-xfrm-prevent-configuration-of-interface-index-when-o.patch
  [xfrm: always initialize offload path]: https://fastswan.org/kernel-patches/0009-xfrm-always-initialize-offload-path.patch
  [xfrm: fix offloading of cross-family tunnels]: https://fastswan.org/kernel-patches/0010-xfrm-fix-offloading-of-cross-family-tunnels.patch
  [net/mlx5e: Update TX ESN context for IPSec hardware offload]: https://fastswan.org/kernel-patches/0001-net-mlx5e-Update-TX-ESN-context-for-IPSec-hardware-o.patch
  [net/mlx5e: Fix inversion dependency warning while enabling IPsec tunnel]: https://fastswan.org/kernel-patches/0002-net-mlx5e-Fix-inversion-dependency-warning-while-ena.patch
  [net/mlx5e: Rely on reqid in IPsec tunnel mode]: https://fastswan.org/kernel-patches/0003-net-mlx5e-Rely-on-reqid-in-IPsec-tunnel-mode.patch
  [net/mlx5e: Always start IPsec sequence number from 1]: https://fastswan.org/kernel-patches/0004-net-mlx5e-Always-start-IPsec-sequence-number-from-1.patch
  [net/mlx5e: Separate address related variables to be in struct]: https://fastswan.org/kernel-patches/0005-net-mlx5e-Separate-address-related-variables-to-be-i.patch
  [net/mlx5e: Properly match IPsec subnet addresses]: https://fastswan.org/kernel-patches/0006-net-mlx5e-Properly-match-IPsec-subnet-addresses.patch
  [net/mlx5e: Support routed networks during IPsec MACs initialization]: https://fastswan.org/kernel-patches/0007-net-mlx5e-Support-routed-networks-during-IPsec-MACs-.patch
  [net/mlx5e: Use ip6_dst_lookup instead of ipv6_dst_lookup_flow for MAC init]: https://fastswan.org/kernel-patches/0008-net-mlx5e-Use-ip6_dst_lookup-instead-of-ipv6_dst_lookup_flow-for-MAC-init.patch
  [net/mlx5e: Trigger neighbor resolution for unresolved destinations]: https://fastswan.org/kernel-patches/0009-net-mlx5e-Trigger-neighbor-resolution-for-unresolved-destinations.patch
  [net/mlx5e: Prevent tunnel reformat when tunnel mode not allowed]: https://fastswan.org/kernel-patches/0010-net-mlx5e-Prevent-tunnel-reformat-when-tunnel-mode-not-allowed.patch

  [kernel/git/leon/linux-rdma.git ipsec-fixes branch]: https://git.kernel.org/pub/scm/linux/kernel/git/leon/linux-rdma.git/log/?h=ipsec-fixes

## strongSwan

Last stable strongSwan supporting hw_offload operations. At the time of writing, [strongSwan version 6.0.0] is a good choice.

  [strongSwan version 6.0.0]: https://strongswan.org/download.html
