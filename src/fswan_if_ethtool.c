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

#include "utils.h"
#include "ethtool.h"
#include "fswan_if.h"
#include "fswan_if_ethtool.h"


/*
 *	Interface ethtool stats collection
 */
static void
update_rate(struct iface_rate *r, uint64_t cur_bytes, uint64_t cur_pkts,
	    uint64_t elapsed)
{
	if (elapsed) {
		/* bits/s, double keeps the math overflow-free at 100G+ rates */
		r->bw_bps = (uint64_t)((double)(cur_bytes - r->prev_bytes)
				       * 8e9 / elapsed);
		r->pps = (cur_pkts - r->prev_pkts) * 1000000000ULL / elapsed;
	}
	r->prev_bytes = cur_bytes;
	r->prev_pkts = cur_pkts;
	gauge_history_push(&r->bw_history, (float) r->bw_bps);
	gauge_history_push(&r->pps_history, (float) r->pps);
}

int
fswan_if_collect_ethtool(struct interface *iface, uint64_t now_ns)
{
	struct ethtool_cache *c = iface->ethtool_cache;
	struct ethtool_phy_stats *ps = &iface->phy_stats;
	struct ethtool_ipsec_stats *is = &iface->ipsec_stats;
	uint64_t *d, elapsed;
	uint32_t q, nr;
	int i;

	/* lazy cache init on first call after interface is up */
	if (!c) {
		uint32_t nr_q = max(iface->nr_rx_queues, iface->nr_tx_queues);
		if (ethtool_gstats_cache_init(&iface->ethtool_cache, iface->ifname,
					      nr_q) < 0)
			return -1;
		c = iface->ethtool_cache;
	}

	if (ethtool_gstats_fetch(c, iface->ifname) < 0)
		return -1;

	/* fill phy_stats */
	for (i = 0, d = (uint64_t *)ps; i < N_PHY_STATS; i++)
		d[i] = ethtool_gstats_val(c, c->phy_idx[i]);

	/* fill ipsec_stats */
	for (i = 0, d = (uint64_t *)is; i < N_IPSEC_STATS; i++)
		d[i] = ethtool_gstats_val(c, c->ipsec_idx[i]);

	/* fill per-queue stats */
	if (iface->queue_stats) {
		nr = max(iface->nr_rx_queues, iface->nr_tx_queues);
		for (q = 0; q < nr; q++) {
			int *qi = &c->q_idx[q * c->n_per_queue];
			d = (uint64_t *)&iface->queue_stats[q];
			for (i = 0; i < N_QUEUE_STATS; i++)
				d[i] = ethtool_gstats_val(c, qi[i]);
		}
	}

	elapsed = iface->prev_ts_ns ? now_ns - iface->prev_ts_ns : 0;
	update_rate(&iface->rx, ps->rx_bytes, ps->rx_packets, elapsed);
	update_rate(&iface->tx, ps->tx_bytes, ps->tx_packets, elapsed);
	update_rate(&iface->ipsec_rx, is->rx_bytes, is->rx_pkts, elapsed);
	update_rate(&iface->ipsec_tx, is->tx_bytes, is->tx_pkts, elapsed);
	iface->prev_ts_ns = now_ns;
	return 0;
}

