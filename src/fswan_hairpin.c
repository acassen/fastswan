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

/* system includes */
#include <string.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <libbpf.h>

/* local includes */
#include "memory.h"
#include "logger.h"
#include "bitops.h"
#include "list_head.h"
#include "inet_utils.h"
#include "fswan_data.h"
#include "fswan_if.h"
#include "fswan_netlink.h"
#include "fswan_bpf_prog.h"
#include "fswan_bpf_xfrm.h"
#include "fswan_hairpin.h"


/* Extern data */
extern struct data *daemon_data;


/*
 *	BPF Map helpers
 */
static struct bpf_map *
fswan_hairpin_map(struct interface *iface)
{
	struct fswan_bpf_prog *p = iface->bpf_prog;

	if (!p || !p->bpf_maps)
		return NULL;
	if (__test_bit(FSWAN_BPF_PROG_FL_SHUTDOWN_BIT, &p->flags))
		return NULL;
	return p->bpf_maps[FSWAN_BPF_MAP_HAIRPIN].map;
}

static int
fswan_hairpin_map_update(struct interface *iface, struct hairpin_nexthop *nh)
{
	struct bpf_map *map = fswan_hairpin_map(iface);
	uint32_t key = iface->ifindex;

	if (!map)
		return 0;

	if (key >= HAIRPIN_MAP_MAX_ENTRIES) {
		log_message(LOG_INFO, "%s(): ifindex %u out of hairpin map range"
				    , __FUNCTION__, key);
		return -1;
	}

	return bpf_map__update_elem(map, &key, sizeof(key),
				    nh, sizeof(*nh), 0);
}


/*
 *	nexthop validation
 */
static struct interface *
fswan_hairpin_egress_match(struct interface *iface, int neigh_ifindex)
{
	struct interface *neigh_iface;

	if (neigh_ifindex == iface->ifindex)
		return iface;

	/* VTY may load hairpin-to-nexthop before the VLAN child's
	 * interface block, so trigger an on-demand RTM_GETLINK for
	 * the oif returned by route lookup.
	 */
	neigh_iface = fswan_if_get_by_ifindex(neigh_ifindex, true);
	if (neigh_iface && neigh_iface->link_iface == iface)
		return neigh_iface;

	return NULL;
}


/*
 *	Reformat builder
 */
static void
fswan_hairpin_build(struct hairpin_nexthop *nh, struct interface *iface,
		    const uint8_t *dst_mac, uint16_t vlan_id)
{
	uint8_t *p = nh->reformat;

	memset(nh, 0, sizeof(*nh));
	memcpy(p, dst_mac, ETH_ALEN);
	p += ETH_ALEN;
	memcpy(p, iface->hw_addr, ETH_ALEN);
	p += ETH_ALEN;
	nh->hdr_len = ETH_HLEN;

	if (vlan_id) {
		*(uint16_t *) p = htons(ETH_P_8021Q);
		p += 2;
		*(uint16_t *) p = htons(vlan_id & 0x0fff);
		p += 2;
		nh->hdr_len += 4;
	}

	*(uint16_t *) p = htons(ETH_P_IP);
}

static int
fswan_hairpin_publish(struct interface *iface)
{
	struct hairpin_nexthop nh;

	fswan_hairpin_build(&nh, iface, iface->hairpin->hw_addr,
			    iface->hairpin->vlan_id);
	return fswan_hairpin_map_update(iface, &nh);
}

static int
fswan_hairpin_unpublish(struct interface *iface)
{
	struct hairpin_nexthop empty = {};

	return fswan_hairpin_map_update(iface, &empty);
}


/*
 *	Hairpin helpers
 */
int
fswan_hairpin_set(struct interface *iface, uint32_t nh_addr)
{
	uint32_t gw = 0;
	int oif = 0;

	if (!iface->hairpin) {
		PMALLOC(iface->hairpin);
		if (!iface->hairpin)
			return -1;
	}

	/* Reset state and clear any stale BPF map slot first */
	iface->hairpin->nh_addr = nh_addr;
	iface->hairpin->via_addr = 0;
	iface->hairpin->resolved = false;
	iface->hairpin->vlan_id = 0;
	memset(iface->hairpin->hw_addr, 0, ETH_ALEN);
	fswan_hairpin_unpublish(iface);

	if (fswan_netlink_route_lookup(nh_addr, &gw, &oif) < 0) {
		log_message(LOG_INFO, "hairpin: %s: no route to nexthop"
				      " %u.%u.%u.%u"
				    , iface->ifname, NIPQUAD(nh_addr));
		return -1;
	}

	if (!fswan_hairpin_egress_match(iface, oif)) {
		log_message(LOG_INFO, "hairpin: %s: route to %u.%u.%u.%u"
				      " via oif %d is neither this iface nor"
				      " a VLAN child of it"
				    , iface->ifname, NIPQUAD(nh_addr), oif);
		return -1;
	}

	iface->hairpin->via_addr = gw ? : nh_addr;

	/* Synchronous neigh resolution. If not in the kernel cache yet,
	 * a later RTM_NEWNEIGH event will fill the slot.
	 */
	fswan_netlink_neigh_lookup(iface->hairpin->via_addr, oif);

	return iface->hairpin->resolved ? 0 : -1;
}

void
fswan_hairpin_clear(struct interface *iface)
{
	if (!iface->hairpin)
		return;

	fswan_hairpin_unpublish(iface);
	FREE(iface->hairpin);
	iface->hairpin = NULL;
}

int
fswan_hairpin_seed(struct interface *iface)
{
	if (!iface->hairpin || !iface->hairpin->resolved)
		return 0;

	return fswan_hairpin_publish(iface);
}

void
fswan_hairpin_neigh_update(uint32_t addr, const uint8_t *lladdr, int ifindex)
{
	struct interface *iface, *egress;

	list_for_each_entry(iface, &daemon_data->interfaces, next) {
		if (!iface->hairpin || iface->hairpin->via_addr != addr)
			continue;

		egress = fswan_hairpin_egress_match(iface, ifindex);
		if (!egress) {
			log_message(LOG_INFO, "hairpin: %s: via %u.%u.%u.%u"
					      " resolved on ifindex %d which is"
					      " neither this iface nor a VLAN"
					      " child of it! ignoring..."
					    , iface->ifname
					    , NIPQUAD(addr)
					    , ifindex);
			continue;
		}

		memcpy(iface->hairpin->hw_addr, lladdr, ETH_ALEN);
		iface->hairpin->vlan_id = egress->vlan_id;
		iface->hairpin->resolved = true;
		fswan_hairpin_publish(iface);
	}
}

void
fswan_hairpin_neigh_delete(uint32_t addr)
{
	struct interface *iface;

	list_for_each_entry(iface, &daemon_data->interfaces, next) {
		if (!iface->hairpin || iface->hairpin->via_addr != addr)
			continue;
		iface->hairpin->resolved = false;
		fswan_hairpin_unpublish(iface);
	}
}

void
fswan_hairpin_route_event(void)
{
	struct interface *iface;

	list_for_each_entry(iface, &daemon_data->interfaces, next) {
		if (!iface->hairpin)
			continue;
		fswan_hairpin_set(iface, iface->hairpin->nh_addr);
	}
}
