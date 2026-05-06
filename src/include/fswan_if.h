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
#include <net/if.h>
#include <linux/if_ether.h>
#include "list_head.h"
#include "ethtool.h"
#include "gauge.h"
#include "fswan_bpf_prog.h"
#include "fswan_hairpin.h"
#include "fswan_flower.h"

/* Per-interface flags */
enum fswan_interface_flags {
	FSWAN_INTERFACE_FL_SHUTDOWN_BIT,
	FSWAN_INTERFACE_FL_RUNNING_BIT,
	FSWAN_INTERFACE_FL_DESTROYING_BIT,
};

/* Types */
struct iface_rate {
	uint64_t		bw_bps;
	uint64_t		pps;
	uint64_t		prev_bytes;
	uint64_t		prev_pkts;
	struct gauge_history	bw_history;
	struct gauge_history	pps_history;
};

struct interface {
	char			ifname[IF_NAMESIZE];
	int			ifindex;
	char			description[128];

	/* L2 attributes from RTM_NEWLINK */
	uint8_t			hw_addr[ETH_ALEN];
	uint16_t		vlan_id;

	/* point to real device if it's a virtual device */
	struct interface	*link_iface;

	/* attached BPF program */
	struct fswan_bpf_prog	*bpf_prog;
	struct list_head	bpf_prog_list;
	struct bpf_link		*bpf_xdp_lnk;

	/* hairpin-to-nexthop config */
	struct fswan_hairpin	*hairpin;

	/* flower-mode (TC HW offload) */
	struct fswan_flower	*flower;

	/* ethtool PHY counters + derived rates */
	struct ethtool_phy_stats phy_stats;
	struct ethtool_ipsec_stats ipsec_stats;
	struct iface_rate	rx;
	struct iface_rate	tx;
	struct iface_rate	ipsec_rx;
	struct iface_rate	ipsec_tx;
	uint64_t		prev_ts_ns;

	/* per-queue ethtool stats */
	uint32_t		nr_rx_queues;
	uint32_t		nr_tx_queues;
	struct ethtool_q_stats	*queue_stats;
	struct ethtool_cache	*ethtool_cache;

	unsigned long		flags;
	struct list_head	next;
};


/* Prototypes */
struct interface *fswan_if_alloc(const char *name, int ifindex);
struct interface *fswan_if_get(const char *name, bool alloc);
struct interface *fswan_if_get_by_ifindex(int ifindex, bool alloc);
void fswan_if_link(struct interface *master, struct interface *slave);
void fswan_if_destroy(struct interface *iface);
void fswan_if_destroy_all(void);
void fswan_if_foreach(int (*hdl)(struct interface *, void *), void *arg);
