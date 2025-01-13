/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Soft:        The main goal of this project is to provide a fast data-path
 *              for the Linux Kernel XFRM layer. Some NIC vendors offer IPSEC
 *              acceleration via a Crypto mode or a Packet mode. In Packet
 *              mode, all IPSEC ESP operations are done by the hardware to
 *              offload the kernel for crypto and packet handling. To further
 *              increase perfs we implement kernel routing offload via XDP.
 *              A XFRM kernel netlink reflector is dynamically andi
 *              transparently mirroring kernel XFRM policies to the XDP layer
 *              for kernel netstack bypass. fastSwan is an XFRM offload feature.
 *
 * Authors:     Alexandre Cassen, <acassen@gmail.com>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU Affero General Public
 *              License Version 3.0 as published by the Free Software Foundation;
 *              either version 3.0 of the License, or (at your option) any later
 *              version.
 *
 * Copyright (C) 2025 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _XFRM_H
#define _XFRM_H

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

/* linux/if_vlan.h have not exposed this as UAPI, thus mirror some here
 *
 *      struct vlan_hdr - vlan header
 *      @h_vlan_TCI: priority and VLAN ID
 *      @h_vlan_encapsulated_proto: packet type ID or len
 */
struct _vlan_hdr {
	__be16	hvlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};

struct parse_pkt {
	struct xdp_md	*ctx;
	__u16	vlan_id;
	__u16   l3_proto;
	__u16   l3_offset;
};

struct ipv4_lpm_key {
	__u32	pfx_len;
	__u32	pfx;
};

struct ipv4_xfrm_policy {
	__be32	src_pfx_mask;
	__be32	src_pfx;
	__u32	ifindex;		

	__u8	flags;
} __attribute__ ((__aligned__(8)));
#define XFRM_POLICY_FL_INGRESS	(1 << 0)
#define XFRM_POLICY_FL_EGRESS	(1 << 1)

struct xfrm_offload_stats {
	__u32	ifindex;
	__u64	rx_pkts;
	__u64	rx_bytes;
	__u64	tx_pkts;
	__u64	tx_bytes;
} __attribute__ ((__aligned__(8)));


#endif
