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
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, XFRM_DST_MAX);
	__uint(key_size, sizeof(struct ipv4_dst_lpm_key));
	__uint(value_size, sizeof(__u32));
} dst_lpm SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, XFRM_POLICY_MAX);
	__uint(key_size, sizeof(struct ipv4_policy_lpm_key));
	__uint(value_size, sizeof(struct ipv4_xfrm_policy));
} policy_lpm SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, XFRM_POLICY_MAX);
	__type(key, __u32);
	__type(value, struct xfrm_policy_stats);
} xfrm_policy_stats_array SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, HAIRPIN_MAP_MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct hairpin_nexthop);
} hairpin_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, IFACE_TOPO_MAP_MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct iface_topo);
} iface_topo SEC(".maps");


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
 *	Stats related
 */
static __always_inline void
xfrm_stats_update(struct xdp_md *ctx, struct ipv4_xfrm_policy *p)
{
	struct xfrm_policy_stats *s;
	__u32 slot = p->stats_slot;

	if (unlikely(!slot))
		return;

	s = bpf_map_lookup_elem(&xfrm_policy_stats_array, &slot);
	if (!s)
		return;

	s->pkts++;
	s->bytes += (ctx->data_end - ctx->data);
}

/*
 *	FIB xmit
 */
static __always_inline int
xfrm_fib_xmit(struct xdp_md *ctx, struct bpf_fib_lookup *fib)
{
	void *data, *data_end;
	struct ethhdr *ethh;

	data     = (void *) (long) ctx->data;
	data_end = (void *) (long) ctx->data_end;
	ethh     = data;
	if ((void *) (ethh + 1) > data_end)
		return XDP_DROP;
	__builtin_memcpy(ethh->h_dest, fib->dmac, ETH_ALEN);
	__builtin_memcpy(ethh->h_source, fib->smac, ETH_ALEN);

	if (ctx->ingress_ifindex == fib->ifindex)
		return XDP_TX;
	return bpf_redirect(fib->ifindex, 0);
}

/*
 *	VLAN xmit
 */
static __always_inline int
xfrm_fib_xmit_vlan(struct xdp_md *ctx, struct bpf_fib_lookup *fib,
		   struct iface_topo *t)
{
	const int vlan_sz = (int) sizeof(struct _vlan_hdr);
	struct _vlan_hdr *vlan;
	void *data, *data_end;
	struct ethhdr *eth;

	if (bpf_xdp_adjust_head(ctx, -vlan_sz))
		return XDP_DROP;

	data     = (void *) (long) ctx->data;
	data_end = (void *) (long) ctx->data_end;
	if (data + ETH_HLEN + vlan_sz > data_end)
		return XDP_DROP;

	eth = data;
	vlan = (void *) (eth + 1);
	__builtin_memcpy(eth->h_dest, fib->dmac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, fib->smac, ETH_ALEN);
	eth->h_proto = bpf_htons(ETH_P_8021Q);
	vlan->hvlan_TCI = bpf_htons(t->vlan_id & 0x0fff);
	/* vlan->h_vlan_encapsulated_proto already holds the original ethertype */

	if (ctx->ingress_ifindex == t->link_ifindex)
		return XDP_TX;
	return bpf_redirect(t->link_ifindex, 0);
}

/*
 *	FIB lookup
 */
static __always_inline int
xfrm_fib_lookup(struct xdp_md *ctx, struct iphdr *iph, struct ipv4_xfrm_policy *p)
{
	struct bpf_fib_lookup fib_params;
	struct iface_topo *t = NULL;
	__u32 idx;
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

	/* TTL + stats while iph is still bounds-valid */
	ip_decrease_ttl(iph);
	xfrm_stats_update(ctx, p);

	idx = fib_params.ifindex;
	if (idx < IFACE_TOPO_MAP_MAX_ENTRIES)
		t = bpf_map_lookup_elem(&iface_topo, &idx);
	if (t && t->vlan_id)
		return xfrm_fib_xmit_vlan(ctx, &fib_params, t);
	return xfrm_fib_xmit(ctx, &fib_params);
}

/*
 *	Hairpin-to-nexthop xmit
 *
 * Input is always untagged (post-IPsec-decap).
 */
static __always_inline int
xfrm_hairpin_xmit(struct xdp_md *ctx, struct iphdr *iph, struct ipv4_xfrm_policy *p)
{
	const int vlan_sz = (int) sizeof(struct _vlan_hdr);
	struct hairpin_nexthop *nh = NULL;
	__u32 ingress = ctx->ingress_ifindex;
	void *data, *data_end;
	bool tagged;

	if (ingress < HAIRPIN_MAP_MAX_ENTRIES)
		nh = bpf_map_lookup_elem(&hairpin_map, &ingress);
	if (!nh || !nh->hdr_len)
		return xfrm_fib_lookup(ctx, iph, p);

	/* TTL while iph is still bounds-valid */
	ip_decrease_ttl(iph);

	tagged = (nh->hdr_len == ETH_HLEN + vlan_sz);
	if (tagged && bpf_xdp_adjust_head(ctx, -vlan_sz))
		return XDP_DROP;

	data = (void *) (long) ctx->data;
	data_end = (void *) (long) ctx->data_end;

	/* Verifier requires constant-size memcpy per branch */
	if (tagged) {
		if (data + ETH_HLEN + vlan_sz > data_end)
			return XDP_DROP;
		__builtin_memcpy(data, nh->reformat, ETH_HLEN + vlan_sz);
	} else {
		if (data + ETH_HLEN > data_end)
			return XDP_DROP;
		__builtin_memcpy(data, nh->reformat, ETH_HLEN);
	}

	xfrm_stats_update(ctx, p);
	return XDP_TX;
}

/*
 *	XFRM Policy lookup
 */
static __always_inline struct ipv4_xfrm_policy *
xfrm_policy_lookup(struct iphdr *iph)
{
	struct ipv4_dst_lpm_key dk = { .prefixlen = 32, .dst = iph->daddr };
	struct ipv4_policy_lpm_key pk;
	__u32 *dst_id;

	dst_id = bpf_map_lookup_elem(&dst_lpm, &dk);
	if (unlikely(!dst_id))
		return NULL;

	pk.prefixlen = 64;
	pk.dst_id = *dst_id;
	pk.src = iph->saddr;
	return bpf_map_lookup_elem(&policy_lpm, &pk);
}

static __always_inline int
xdp_xfrm_offload(struct parse_pkt *pkt)
{
	void *data_end = (void *) (long) pkt->ctx->data_end;
	void *data = (void *) (long) pkt->ctx->data;
	struct ipv4_xfrm_policy *p;
	struct iphdr *iph;

	iph = data + pkt->l3_offset;
	if (unlikely((void *) (iph + 1) > data_end))
		return XDP_PASS;

	p = xfrm_policy_lookup(iph);
	if (!p)
		return XDP_PASS;

	/* Egress policy simply redirect to policy ifindex.
	 * HW learnt Layer2 src and dst MAC during XFRM policy
	 * offload settings. */
	if (p->flags & XFRM_POLICY_FL_EGRESS) {
		ip_decrease_ttl(iph);
		xfrm_stats_update(pkt->ctx, p);

		if (pkt->ctx->ingress_ifindex == p->ifindex)
			return XDP_TX;

		return bpf_redirect(p->ifindex, 0);
	}

	return xfrm_hairpin_xmit(pkt->ctx, iph, p);
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
	if (unlikely((void *) eth + offset > data_end))
		return false;

	eth_type = eth->h_proto;

	/* Handle outer VLAN tag */
	if (eth_type == bpf_htons(ETH_P_8021Q) ||
	    eth_type == bpf_htons(ETH_P_8021AD)) {
		vlan_hdr = (void *) eth + offset;
		vlan = bpf_ntohs(vlan_hdr->hvlan_TCI);
		pkt->vlan_id = vlan & 0x0fff;
		offset += sizeof (*vlan_hdr);
		if (unlikely((void *) eth + offset > data_end))
			return false;

		eth_type = vlan_hdr->h_vlan_encapsulated_proto;
	}

	/* FIXME: Add support to IPv6 */
	if (eth_type != bpf_htons(ETH_P_IP))
		return false;

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
