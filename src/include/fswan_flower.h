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

struct interface;
struct xfrm_policy;


/* Selector fields match struct fswan_flower_sel exactly so a rule can
 * be passed to the netlink layer without renaming.
 */
struct fswan_flower_rule {
	struct rb_node		node;
	uint32_t		handle;
	__be32			saddr;
	__be32			daddr;
	uint8_t			prefixlen_s;
	uint8_t			prefixlen_d;
	uint16_t		vlan_id;
};

struct fswan_flower {
	uint32_t		next_handle;	/* monotonic, starts at 1 */
	struct rb_root		rules;
};


/* Public surface */
int fswan_flower_enable(struct interface *iface);
void fswan_flower_disable(struct interface *iface);
int fswan_flower_xfrm_action(int action, struct interface *iface,
			     struct xfrm_policy *p);
bool fswan_flower_policy_counters(struct interface *iface,
				  const struct xfrm_policy *p,
				  uint64_t *pkts, uint64_t *bytes);
void fswan_flower_counter_cache_begin(void);
void fswan_flower_counter_cache_end(void);
