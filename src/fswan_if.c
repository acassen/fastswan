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

/* global includes */
#include <stdlib.h>
#include <string.h>
#include <net/if.h>

/* local includes */
#include "memory.h"
#include "bitops.h"
#include "utils.h"
#include "list_head.h"
#include "ethtool.h"
#include "fswan_data.h"
#include "fswan_if.h"
#include "fswan_netlink.h"
#include "fswan_monitor.h"
#include "fswan_bpf_prog.h"


/* Extern data */
extern struct data *daemon_data;


/*
 * ifindex is resolved lazily via if_nametoindex when the operator
 * enters the `interface NAME` block.
 */
struct interface *
fswan_if_get_by_ifindex(int ifindex, bool alloc)
{
	struct interface *iface;

	if (ifindex <= 0)
		return NULL;

	list_for_each_entry(iface, &daemon_data->interfaces, next) {
		if (iface->ifindex == ifindex)
			return iface;
	}

	if (alloc && !fswan_netlink_if_lookup(ifindex))
		return fswan_if_get_by_ifindex(ifindex, false);

	return NULL;
}

struct interface *
fswan_if_alloc(const char *name, int ifindex)
{
	struct interface *new;
	uint32_t nr_rx = 0, nr_tx = 0, nr;

	PMALLOC(new);
	strlcpy(new->ifname, name, IF_NAMESIZE);
	new->ifindex = ifindex;
	INIT_LIST_HEAD(&new->bpf_prog_list);
	INIT_LIST_HEAD(&new->next);
	__set_bit(FSWAN_INTERFACE_FL_SHUTDOWN_BIT, &new->flags);

	ethtool_get_nr_queues(name, &nr_rx, &nr_tx);
	nr = max(nr_rx, nr_tx);
	if (nr) {
		new->queue_stats = calloc(nr, sizeof(*new->queue_stats));
		new->nr_rx_queues = nr_rx;
		new->nr_tx_queues = nr_tx;
	}

	list_add_tail(&new->next, &daemon_data->interfaces);
	return new;
}

struct interface *
fswan_if_get(const char *name, bool alloc)
{
	struct interface *iface;
	int ifindex;

	list_for_each_entry(iface, &daemon_data->interfaces, next) {
		if (!strcmp(iface->ifname, name))
			return iface;
	}

	if (!alloc)
		return NULL;

	ifindex = if_nametoindex(name);
	if (ifindex && !fswan_netlink_if_lookup(ifindex))
		return fswan_if_get_by_ifindex(ifindex, false);

	return NULL;
}

void
fswan_if_link(struct interface *master, struct interface *slave)
{
	slave->link_iface = master;
}

void
fswan_if_destroy(struct interface *iface)
{
	struct interface *child;

	__set_bit(FSWAN_INTERFACE_FL_DESTROYING_BIT, &iface->flags);
	fswan_monitor_iface_quiesce();
	list_head_del(&iface->next);

	if (iface->bpf_prog) {
		fswan_bpf_prog_detach(iface->bpf_prog, iface);
		list_head_del(&iface->bpf_prog_list);
		iface->bpf_prog = NULL;
	}

	if (iface->ethtool_cache) {
		ethtool_gstats_cache_destroy(iface->ethtool_cache);
		iface->ethtool_cache = NULL;
	}
	if (iface->queue_stats) {
		free(iface->queue_stats);
		iface->queue_stats = NULL;
	}

	list_for_each_entry(child, &daemon_data->interfaces, next) {
		if (child->link_iface == iface)
			child->link_iface = NULL;
	}

	FREE(iface);
}

void
fswan_if_destroy_all(void)
{
	struct interface *iface, *tmp;

	list_for_each_entry_safe(iface, tmp, &daemon_data->interfaces, next)
		fswan_if_destroy(iface);
}

void
fswan_if_foreach(int (*hdl)(struct interface *, void *), void *arg)
{
	struct interface *iface;

	list_for_each_entry(iface, &daemon_data->interfaces, next)
		(*hdl)(iface, arg);
}
