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

#ifndef _FSWAN_BPF_XFRM_H
#define _FSWAN_BPF_XFRM_H


/* MAP Entries*/
enum {
	FSWAN_BPF_MAP_IPV4_LPM = 0,
	FSWAN_BPF_MAP_POLICY_STATS_HASH,
	FSWAN_BPF_MAP_STATS_HASH,
	FSWAN_BPF_MAP_CNT
};

#define XFRM_POLICY_FL_INGRESS	(1 << 0)
#define XFRM_POLICY_FL_EGRESS	(1 << 1)
#define XFRM_POLICY_FL_NO_STATS	(1 << 2)

struct ipv4_lpm_key {
	__u32	pfx_len;
	__u32	pfx;
};

struct ipv4_xfrm_policy {
	__u32	pfx_len;
	__u32	pfx;
	__be32	src_pfx_mask;
	__be32	src_pfx;
	__u32	ifindex;

	__u8	flags;
} __attribute__ ((__aligned__(8)));

struct xfrm_policy_stats {
	__u64	pkts;
	__u64	bytes;
} __attribute__ ((__aligned__(8)));

struct xfrm_offload_stats {
	__u32	ifindex;
	__u64	rx_pkts;
	__u64	rx_bytes;
	__u64	tx_pkts;
	__u64	tx_bytes;
} __attribute__ ((__aligned__(8)));


/* Prototypes */
extern int fswan_xfrm_policy_vty(vty_t *);
extern int fswan_xfrm_policy_stats_vty(vty_t *);
extern int fswan_xfrm_stats_vty(vty_t *);
extern int fswan_bpf_xfrm_stats_init(fswan_bpf_opts_t *);
extern int fswan_bpf_xfrm_load(fswan_bpf_opts_t *);
extern int fswan_bpf_xfrm_action(int, xfrm_policy_t *);

#endif
