# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Soft:        The main goal of this project is to provide a fast data-path
#              for the Linux Kernel XFRM layer. Some NIC vendors offer IPSEC
#              acceleration via a Crypto mode or a Packet mode. In Packet
#              mode, all IPSEC ESP operations are done by the hardware to
#              offload the kernel for crypto and packet handling. To further
#              increase perfs we implement kernel routing offload via XDP.
#              A XFRM kernel netlink reflector is dynamically and
#              transparently mirroring kernel XFRM policies to the XDP layer
#              for kernel netstack bypass. fastSwan is an XFRM offload feature.
#
# Authors:     Alexandre Cassen, <acassen@gmail.com>
#
#              This program is free software; you can redistribute it and/or
#              modify it under the terms of the GNU Affero General Public
#              License Version 3.0 as published by the Free Software Foundation;
#              either version 3.0 of the License, or (at your option) any later
#              version.
#
# Copyright (C) 2025-2026 Alexandre Cassen, <acassen@gmail.com>
#

subdir('bpf')

src += files(
  'fswan_bpf.c',
  'fswan_bpf_prog.c',
  'fswan_bpf_prog_vty.c',
  'fswan_bpf_xfrm.c',
  'fswan_cpu.c',
  'fswan_cpu_vty.c',
  'fswan_flower.c',
  'fswan_hairpin.c',
  'fswan_monitor.c',
  'fswan_monitor_vty.c',
  'fswan_data.c',
  'fswan_if.c',
  'fswan_if_ethtool.c',
  'fswan_if_rxq.c',
  'fswan_if_vty.c',
  'fswan_netlink.c',
  'fswan_netlink_flower.c',
  'fswan_netlink_xfrm.c',
  'fswan_vty.c',
  'fswan_vty_shell.c',
  'fswan_xfrm_vty.c',
  'main.c',
)

inc += include_directories('include')
