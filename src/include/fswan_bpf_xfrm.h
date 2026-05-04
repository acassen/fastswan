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
#pragma once

#include <stdbool.h>
#include <linux/types.h>

#include "vty.h"
#include "fswan_bpf_prog.h"
#include "fswan_netlink.h"

/* MAP Entries*/
enum {
	FSWAN_BPF_MAP_DST_LPM = 0,
	FSWAN_BPF_MAP_POLICY_LPM,
	FSWAN_BPF_MAP_POLICY_STATS_ARRAY,
	FSWAN_BPF_MAP_HAIRPIN,
	FSWAN_BPF_MAP_CNT
};

#define XFRM_POLICY_FL_INGRESS	(1 << 0)
#define XFRM_POLICY_FL_EGRESS	(1 << 1)

#define XFRM_POLICY_MAX		262144
#define XFRM_DST_MAX		65536

struct ipv4_dst_lpm_key {
	__u32	prefixlen;
	__be32	dst;
};

struct ipv4_policy_lpm_key {
	__u32	prefixlen;
	__u32	dst_id;
	__be32	src;
};

struct ipv4_xfrm_policy {
	__u32	ifindex;
	__u32	stats_slot;
	__u8	flags;
} __attribute__ ((__aligned__(8)));

struct xfrm_policy_stats {
	__u64	pkts;
	__u64	bytes;
} __attribute__ ((__aligned__(8)));

/* Hairpin-to-nexthop reformat record (mirror of struct in src/bpf/xfrm.h) */
#define HAIRPIN_REFORMAT_MAX	18
#define HAIRPIN_CACHELINE	64
#define HAIRPIN_MAP_MAX_ENTRIES	1024

struct hairpin_nexthop {
	__u8	hdr_len;
	__u8	reformat[HAIRPIN_REFORMAT_MAX];
	__u8	_pad[HAIRPIN_CACHELINE - 1 - HAIRPIN_REFORMAT_MAX];
} __attribute__ ((aligned(HAIRPIN_CACHELINE)));


/* Prototypes */
int fswan_xfrm_policy_vty(struct vty *vty);
void fswan_bpf_xfrm_policy_counters_vty(struct vty *vty,
					struct fswan_bpf_prog *opts,
					struct ipv4_xfrm_policy *val);
void fswan_bpf_xfrm_policy_counters_by_selector_vty(struct vty *vty,
						    __be32 saddr, __u8 prefixlen_s,
						    __be32 daddr, __u8 prefixlen_d);
bool fswan_bpf_xfrm_policy_counters_by_selector_sum(__be32 saddr, __u8 prefixlen_s,
						    __be32 daddr, __u8 prefixlen_d,
						    uint64_t *pkts_out,
						    uint64_t *bytes_out);
int fswan_bpf_xfrm_map_load(struct fswan_bpf_prog *p);
int fswan_bpf_xfrm_action(int, struct xfrm_policy *);
