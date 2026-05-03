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

#include <stdint.h>
#include "ethtool.h"
#include "gauge.h"


/* One direction's rate estimates plus their EWMA-smoothed versions. */
struct percpu_rate {
	uint64_t		bw_bps;
	uint64_t		pps;
	double			bw_bps_ewma;
	double			pps_ewma;
};

struct fswan_percpu_metrics {
	float			load;			/* [0.0, 1.0] */
	float			load_ewma;		/* EWMA-smoothed load */
	struct gauge_history	load_history;

	/* Accumulation fields: zeroed before each ethtool tick. */
	struct ethtool_q_stats	q_stats;
	struct ethtool_q_stats	prev_q_stats;

	/* Rate estimates derived from q_stats deltas. */
	struct percpu_rate	rx;
	struct percpu_rate	tx;
	uint64_t		total_bw_bps;
	double			total_bw_bps_ewma;
	uint64_t		rx_buff_alloc_err_rate;

	/* Traffic rate history (fed every ethtool tick, ~3s per sample) */
	struct gauge_history	bw_history;
	struct gauge_history	pps_history;
};

/* Prototypes */
int fswan_percpu_init(void);
void fswan_percpu_destroy(void);
void fswan_percpu_sample_all(uint64_t now_ns);
void fswan_percpu_rates_update(uint64_t now_ns);
void fswan_percpu_load_update_all(void);
void fswan_percpu_publish(void);
const struct fswan_percpu_metrics *fswan_percpu_metrics_get(int cpu);
