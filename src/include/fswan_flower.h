/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Soft:        The main goal of this project is to provide a fast data-path
 *              for the Linux Kernel XFRM layer. Some NIC vendors offer IPSEC
 *              acceleration via a Crypto mode or a Packet mode. In Packet
 *              mode, all IPSEC ESP operations are done by the hardware to
 *              offload the kernel for crypto and packet handling. To further
 *              increase perfs we implement kernel routing offload via XDP.
 *              A XFRM kernel netlink reflector is dynamically and
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
 * Copyright (C) 2025-2026 Alexandre Cassen, <acassen@gmail.com>
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <linux/types.h>

#include "rbtree_types.h"
#include "fswan_netlink_flower.h"

struct interface;
struct xfrm_policy;


struct fswan_flower_rule {
	struct rb_node		node;
	uint32_t		handle;
	struct fswan_flower_sel	sel;

	/* outbound */
	uint16_t		match_vlan_id;

	/* inbound */
	uint8_t			dst_mac[ETH_ALEN];
	uint8_t			src_mac[ETH_ALEN];
	uint16_t		push_vlan_id;
	uint32_t		nh_addr;	/* via, same value for hairpin-backed */
	int			oif;
};

struct fswan_flower_side {
	uint32_t		next_handle;	/* monotonic, starts at 1 */
	struct rb_root		rules;
	uint16_t		chain;		/* 0 for out, configured value for in */
	bool			warmed_up;
};

struct fswan_flower {
	struct fswan_flower_side	*out;	/* NULL when outbound XDP fallback */
	struct fswan_flower_side	*in;	/* NULL when inbound XDP fallback */
	bool				decrement_ttl;
};


/* Public surface. Outbound and inbound are independent: either can run on
 * flower while the other falls back to XDP. The wrapper struct comes and
 * goes with the first/last active side. */
int fswan_flower_enable_out(struct interface *iface);
int fswan_flower_enable_in(struct interface *iface, uint16_t chain);
void fswan_flower_disable_out(struct interface *iface);
void fswan_flower_disable_in(struct interface *iface);
void fswan_flower_disable(struct interface *iface);	/* full teardown */
int fswan_flower_xfrm_action(int action, struct interface *iface,
			     struct xfrm_policy *p);
bool fswan_flower_policy_counters(struct interface *iface,
				  const struct xfrm_policy *p,
				  uint64_t *pkts, uint64_t *bytes);
void fswan_flower_counter_cache_begin(void);
void fswan_flower_counter_cache_end(void);

/* Event hooks called from the netlink filter and from fswan_hairpin. */
void fswan_flower_neigh_update(uint32_t addr, const uint8_t *lladdr,
			       int ifindex);
void fswan_flower_neigh_delete(uint32_t addr);
void fswan_flower_inbound_rebuild(struct interface *iface);
