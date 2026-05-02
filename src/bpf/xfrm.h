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

/* Two-stage LPM matching.
 *
 * Stage 1: dst_lpm maps a dst prefix to a fixed 32-bit dst_id token.
 * Stage 2: policy_lpm is keyed on (dst_id, src), prefixlen = 32 + src_bits.
 */
struct ipv4_dst_lpm_key {
	__u32	prefixlen;	/* 0..32 */
	__be32	dst;
};

struct ipv4_policy_lpm_key {
	__u32	prefixlen;	/* 32..64; 32 + src_bits */
	__u32	dst_id;
	__be32	src;
};

#define XFRM_POLICY_MAX		262144	/* policy_lpm + stats slot capacity */
#define XFRM_DST_MAX		65536	/* dst_lpm + dst_id token capacity */

struct ipv4_xfrm_policy {
	__u32	ifindex;
	__u32	stats_slot;
	__u8	flags;
} __attribute__ ((__aligned__(8)));
#define XFRM_POLICY_FL_INGRESS	(1 << 0)
#define XFRM_POLICY_FL_EGRESS	(1 << 1)
#define XFRM_POLICY_FL_NO_STATS	(1 << 2)

struct xfrm_policy_stats {
	__u64	pkts;
	__u64	bytes;
} __attribute__ ((__aligned__(8)));

/* Hairpin-to-nexthop reformat record. One cache line per entry */
#define HAIRPIN_REFORMAT_MAX	18	/* ETH_HLEN(14) + VLAN_HLEN(4) */
#define HAIRPIN_CACHELINE	64
#define HAIRPIN_MAP_MAX_ENTRIES	1024

struct hairpin_nexthop {
	__u8	hdr_len;
	__u8	reformat[HAIRPIN_REFORMAT_MAX];
	__u8	_pad[HAIRPIN_CACHELINE - 1 - HAIRPIN_REFORMAT_MAX];
} __attribute__ ((aligned(HAIRPIN_CACHELINE)));


#endif
