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

#define KBUILD_MODNAME "xfrm_offload"
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <sys/socket.h>
#include <uapi/linux/bpf.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include "xfrm.h"

/*
 *	MAPs
 */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(key_size, sizeof(struct ipv4_lpm_key));
	__uint(value_size, sizeof(struct ipv4_xfrm_policy));
	__uint(max_entries, 1024);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} ipv4_xfrm_policy_lpm SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __u32);
	__uint(max_entries, 32);
	__type(value, struct xfrm_offload_stats);
} xfrm_offload_stats_hash SEC(".maps");


/*
 *	Stats related
 */
static __always_inline int
xfrm_stats_update(struct xdp_md *ctx, int ifindex_egress, struct ipv4_xfrm_policy *p)
{
	struct xfrm_offload_stats *ingress_stats, *egress_stats;
	__u32 ifindex_ingress = ctx->ingress_ifindex;

	if (p->flags & XFRM_POLICY_FL_NO_STATS)
		return 0;

	p->pkts++;
	p->bytes += (ctx->data_end - ctx->data);

	ingress_stats = bpf_map_lookup_elem(&xfrm_offload_stats_hash, &ifindex_ingress);
	if (!ingress_stats)
		return -1;

	ingress_stats->rx_pkts++;
	ingress_stats->rx_bytes += (ctx->data_end - ctx->data);
	if (ifindex_ingress == ifindex_egress) {
		ingress_stats->tx_pkts++;
		ingress_stats->tx_bytes += (ctx->data_end - ctx->data);
		return 0;
	}

	egress_stats = bpf_map_lookup_elem(&xfrm_offload_stats_hash, &ifindex_egress);
	if (!egress_stats)
		return -1;

	egress_stats->tx_pkts++;
	egress_stats->tx_bytes += (ctx->data_end - ctx->data);
	return 0;
}

/*
 *	IP header related update
 */
static __always_inline int
ip_decrease_ttl(struct iphdr *iph)
{
	__u32 check = (__u32) iph->check;

	check += (__u32) bpf_htons(0x0100);
	iph->check = (__sum16) (check + (check >= 0xFFFF));
	return --iph->ttl;
}

/*
 *	FIB lookup
 */
static __always_inline int
xfrm_fib_lookup(struct xdp_md *ctx, struct ethhdr *ethh, struct iphdr *iph, struct ipv4_xfrm_policy *p)
{
	struct bpf_fib_lookup fib_params;
	int ret;

	__builtin_memset(&fib_params, 0, sizeof(fib_params));
	fib_params.ifindex	= ctx->ingress_ifindex;
	fib_params.family	= AF_INET;
	fib_params.l4_protocol	= iph->protocol;
	fib_params.tot_len	= bpf_ntohs(iph->tot_len);
	fib_params.ipv4_src	= iph->saddr;
	fib_params.ipv4_dst	= iph->daddr;
	ret = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), BPF_FIB_LOOKUP_DIRECT);

	/* Keep in mind that forwarding need to be enabled
	 * on interface we may need to redirect traffic to/from
	 */
	if (ret != BPF_FIB_LKUP_RET_SUCCESS)
		return XDP_PASS;

	/* Ethernet playground */
	__builtin_memcpy(ethh->h_dest, fib_params.dmac, ETH_ALEN);
	__builtin_memcpy(ethh->h_source, fib_params.smac, ETH_ALEN);

	/* IPv4 Header TTL playground */
	ip_decrease_ttl(iph);
	xfrm_stats_update(ctx, fib_params.ifindex, p);

	if (ctx->ingress_ifindex == fib_params.ifindex)
		return XDP_TX;

	return bpf_redirect(fib_params.ifindex, 0);
}

/*
 *	XFRM Policy check
 */
static __always_inline int
xdp_xfrm_offload(struct parse_pkt *pkt)
{
	void *data_end = (void *) (long) pkt->ctx->data_end;
	void *data = (void *) (long) pkt->ctx->data;
	struct ipv4_xfrm_policy *p;
	struct ipv4_lpm_key k;
	struct ethhdr *ethh;
	struct iphdr *iph;

	ethh = data;
	iph = data + pkt->l3_offset;
	if (iph + 1 > data_end)
		return XDP_PASS;

	/* FIXME: Add support to IPv6 */
	if (ethh->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	/* XFRM Policy match */
	k.pfx = iph->daddr;
	k.pfx_len = 32;
	p = bpf_map_lookup_elem(&ipv4_xfrm_policy_lpm, &k);
	if (!p)
		return XDP_PASS;

	/* offload if src prefix match.
	 * FIXME: Maybe extend this to multi-lpm match ? */
	if ((iph->saddr & p->src_pfx_mask) != p->src_pfx)
		return XDP_PASS;

	/* Egress policy simply redirect to policy ifindex.
	 * HW learnt Layer2 src and dst MAC during XFRM policy
	 * offload settings. */
	if (p->flags & XFRM_POLICY_FL_EGRESS) {
		ip_decrease_ttl(iph);
		xfrm_stats_update(pkt->ctx, p->ifindex, p);

		if (pkt->ctx->ingress_ifindex == p->ifindex)
			return XDP_TX;

		return bpf_redirect(p->ifindex, 0);
	}

	return xfrm_fib_lookup(pkt->ctx, ethh, iph, p);
}

/*
 *	Ethernet frame parsing and sanitize
 */
static __always_inline bool
parse_eth_frame(struct parse_pkt *pkt)
{
	void *data_end = (void *) (long) pkt->ctx->data_end;
	void *data = (void *) (long) pkt->ctx->data;
	struct _vlan_hdr *vlan_hdr;
	struct ethhdr *eth = data;
	__u16 eth_type, vlan = 0;
	__u8 offset;

	offset = sizeof(*eth);

	/* Make sure packet is large enough for parsing eth */
	if ((void *) eth + offset > data_end)
		return false;

	eth_type = eth->h_proto;

	/* Handle outer VLAN tag */
	if (eth_type == bpf_htons(ETH_P_8021Q) ||
	    eth_type == bpf_htons(ETH_P_8021AD)) {
		vlan_hdr = (void *) eth + offset;
		vlan = bpf_ntohs(vlan_hdr->hvlan_TCI);
		pkt->vlan_id = vlan & 0x0fff;
		offset += sizeof (*vlan_hdr);
		if ((void *) eth + offset > data_end)
			return false;

		eth_type = vlan_hdr->h_vlan_encapsulated_proto;
		vlan_hdr->hvlan_TCI = bpf_htons(pkt->vlan_id);
	}

	pkt->l3_proto = bpf_ntohs(eth_type);
	pkt->l3_offset = offset;
	return true;
}


SEC("xdp")
int xfrm_offload(struct xdp_md *ctx)
{
	struct parse_pkt pkt = { .ctx = ctx,
				 .vlan_id = 0,
				 .l3_proto = 0,
				 .l3_offset = 0
			       };

	if (!parse_eth_frame(&pkt))
		return XDP_PASS;

	return xdp_xfrm_offload(&pkt);
}

char _license[] SEC("license") = "GPL";
