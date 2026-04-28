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

#include "list_head.h"
#include "ethtool.h"

/* Forward declarations */
struct bpf_link;
struct fswan_bpf_prog;

/* Per-interface flags */
enum fswan_interface_flags {
	FSWAN_INTERFACE_FL_SHUTDOWN_BIT,
	FSWAN_INTERFACE_FL_RUNNING_BIT,
};

/* Types */
struct interface {
	char			ifname[IF_NAMESIZE];
	int			ifindex;
	char			description[128];

	/* point to real device if it's a virtual device */
	struct interface	*link_iface;

	/* attached BPF program */
	struct fswan_bpf_prog	*bpf_prog;
	struct list_head	bpf_prog_list;	/* in bpf_prog->iface_bind_list */
	struct bpf_link		*bpf_xdp_lnk;

	/* xfrm-offload aggregate counters (BPF map readback) */
	uint64_t		rx_pkts;
	uint64_t		rx_bytes;
	uint64_t		tx_pkts;
	uint64_t		tx_bytes;

	/* ethtool PHY counters + derived rates (refreshed every ETHTOOL_POLL_TICKS) */
	struct ethtool_phy_stats phy_stats;
	uint64_t		rx_bw_bps;
	uint64_t		tx_bw_bps;
	uint64_t		rx_pps;
	uint64_t		tx_pps;
	uint64_t		prev_rx_bytes;
	uint64_t		prev_tx_bytes;
	uint64_t		prev_rx_packets;
	uint64_t		prev_tx_packets;
	uint64_t		prev_ts_ns;

	/* per-queue ethtool stats; array of max(nr_rx_queues, nr_tx_queues) */
	uint32_t		nr_rx_queues;
	uint32_t		nr_tx_queues;
	struct ethtool_q_stats	*queue_stats;
	struct ethtool_cache	*ethtool_cache;

	unsigned long		flags;
	struct list_head	next;		/* in daemon_data->interfaces */
};


/* Prototypes */
struct interface *fswan_if_alloc(const char *name, int ifindex);
struct interface *fswan_if_get(const char *name, bool alloc);
struct interface *fswan_if_get_by_ifindex(int ifindex, bool alloc);
void fswan_if_link(struct interface *master, struct interface *slave);
void fswan_if_destroy(struct interface *iface);
void fswan_if_destroy_all(void);
void fswan_if_foreach(int (*hdl)(struct interface *, void *), void *arg);
