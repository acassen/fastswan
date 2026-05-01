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
#include <linux/if_ether.h>
#include "fswan_if.h"

/* hairpin-to-nexthop per-interface state */
struct fswan_hairpin {
	uint32_t	nh_addr;		/* IPv4 nexthop, network order */
	uint8_t		hw_addr[ETH_ALEN];	/* resolved next-hop MAC */
	uint16_t	vlan_id;		/* egress VLAN id, 0 = untagged */
	bool		resolved;
};

/* Public surface */
int fswan_hairpin_set(struct interface *iface, uint32_t nh_addr);
void fswan_hairpin_clear(struct interface *iface);
int fswan_hairpin_seed(struct interface *iface);
void fswan_hairpin_neigh_update(uint32_t addr, const uint8_t *lladdr, int ifindex);
void fswan_hairpin_neigh_delete(uint32_t addr);
