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
the mlx5 Driver and XFRM subsystem. Produced patches has been merged into the Linux
Kernel mainline.

## strongSwan

Last stable strongSwan supporting hw_offload operations. At the time of writing, [strongSwan version 6.0.0] is a good choice.

  [strongSwan version 6.0.0]: https://strongswan.org/download.html
