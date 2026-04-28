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

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "logger.h"
#include "utils.h"
#include "thread.h"
#include "vty_gauge.h"
#include "cpu.h"
#include "ethtool.h"
#include "fswan_data.h"
#include "fswan_if.h"
#include "fswan_if_ethtool.h"
#include "fswan_if_rxq.h"
#include "fswan_cpu.h"

/* Local data */
struct cpu_load *cpu_load;
static struct fswan_percpu_metrics *percpu_metrics;
static int ethtool_tick;
static uint64_t percpu_prev_ts_ns;

/* Extern data */
extern struct data *daemon_data;
extern struct thread_master *master;


/*
 *	Per-CPU workload aggregation
 */
static void
fswan_percpu_reset_accum(void)
{
	int i;

	for (i = 0; i < cpu_load->nr_cpus; i++) {
		struct fswan_percpu_metrics *m = &percpu_metrics[i];
		memset(&m->q_stats, 0, sizeof(m->q_stats));
	}
}

static int
fswan_percpu_collect(struct interface *iface, __attribute__((unused)) void *arg)
{
	int cpu_per_q[iface->nr_rx_queues ? : 1];
	uint32_t q, nr;
	int cpu;
	if (!iface->queue_stats)
		return 0;

	nr = max(iface->nr_rx_queues, iface->nr_tx_queues);

	memset(cpu_per_q, -1, sizeof(cpu_per_q));
	fswan_if_rxq_cpu(iface, cpu_per_q, iface->nr_rx_queues);

	for (q = 0; q < nr; q++) {
		struct ethtool_q_stats *s = &iface->queue_stats[q];

		cpu = (q < iface->nr_rx_queues) ? cpu_per_q[q] : -1;
		if (cpu < 0 || cpu >= cpu_load->nr_cpus)
			continue;
		ethtool_q_stats_add(&percpu_metrics[cpu].q_stats, s);
	}

	return 0;
}

struct fswan_percpu_metrics *
fswan_percpu_metrics_get(int cpu)
{
	if (!percpu_metrics || cpu < 0 || cpu >= cpu_load->nr_cpus)
		return NULL;
	return &percpu_metrics[cpu];
}


static void
fswan_percpu_rates_update(uint64_t now_ns)
{
	uint64_t elapsed = now_ns - percpu_prev_ts_ns;
	int i;

	for (i = 0; i < cpu_load->nr_cpus; i++) {
		struct fswan_percpu_metrics *m = &percpu_metrics[i];

		if (elapsed && percpu_prev_ts_ns) {
			m->rx_bw_bps = (m->q_stats.rx_bytes - m->prev_q_stats.rx_bytes)
				       * 1000000000ULL / elapsed;
			m->tx_bw_bps = (m->q_stats.tx_bytes - m->prev_q_stats.tx_bytes)
				       * 1000000000ULL / elapsed;
			m->total_bw_bps = m->rx_bw_bps + m->tx_bw_bps;
			m->rx_pps = (m->q_stats.rx_packets - m->prev_q_stats.rx_packets)
				    * 1000000000ULL / elapsed;
			m->tx_pps = (m->q_stats.tx_packets - m->prev_q_stats.tx_packets)
				    * 1000000000ULL / elapsed;
			m->rx_buff_alloc_err_rate = (m->q_stats.rx_buff_alloc_err - m->prev_q_stats.rx_buff_alloc_err)
						    * 1000000000ULL / elapsed;
		}
		/* EWMA smoothing on traffic rates */
		m->rx_bw_bps_ewma = EWMA_DEFAULT_ALPHA * m->rx_bw_bps
				   + (1.0 - EWMA_DEFAULT_ALPHA) * m->rx_bw_bps_ewma;
		m->tx_bw_bps_ewma = EWMA_DEFAULT_ALPHA * m->tx_bw_bps
				   + (1.0 - EWMA_DEFAULT_ALPHA) * m->tx_bw_bps_ewma;
		m->total_bw_bps_ewma = EWMA_DEFAULT_ALPHA * m->total_bw_bps
				     + (1.0 - EWMA_DEFAULT_ALPHA) * m->total_bw_bps_ewma;
		m->rx_pps_ewma = EWMA_DEFAULT_ALPHA * m->rx_pps
			       + (1.0 - EWMA_DEFAULT_ALPHA) * m->rx_pps_ewma;
		m->tx_pps_ewma = EWMA_DEFAULT_ALPHA * m->tx_pps
			       + (1.0 - EWMA_DEFAULT_ALPHA) * m->tx_pps_ewma;

		/* push into history rings for slope-based scheduling */
		gauge_history_push(&m->bw_history, (float) m->total_bw_bps);
		gauge_history_push(&m->pps_history, (float) (m->rx_pps + m->tx_pps));

		m->prev_q_stats = m->q_stats;
	}
	percpu_prev_ts_ns = now_ns;
}


/*
 *	Polling thread
 */
static void
fswan_cpu_poll(struct thread *t)
{
	struct timespec ts;
	uint64_t now_ns;
	float load;
	int i;

	(void)t;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	now_ns = timespec_to_ns(&ts);

	cpu_load_update(cpu_load);
	fswan_percpu_reset_accum();

	/* collect ethtool stats every 3s */
	if (++ethtool_tick >= ETHTOOL_POLL_TICKS) {
		ethtool_tick = 0;
		fswan_if_foreach(fswan_if_collect, &now_ns);
		fswan_if_foreach(fswan_percpu_collect, NULL);

		/* Avoid syscall latency */
		clock_gettime(CLOCK_MONOTONIC, &ts);
		now_ns = timespec_to_ns(&ts);
		fswan_percpu_rates_update(now_ns);
	}

	for (i = 0; i < cpu_load->nr_cpus; i++) {
		load = cpu_load_get(cpu_load, i);
		if (load < 0.0f)
			continue;	/* offline CPU */
		gauge_history_push(&percpu_metrics[i].load_history, load);
		percpu_metrics[i].load = load;
		percpu_metrics[i].load_ewma = EWMA_DEFAULT_ALPHA * load
					    + (1.0f - EWMA_DEFAULT_ALPHA) * percpu_metrics[i].load_ewma;
	}

	thread_add_timer(master, fswan_cpu_poll, NULL, TIMER_HZ / 5);
}


/*
 *	CPU monitoring init
 */
int
fswan_cpu_init(void)
{
	if (cpu_load_init_tsc(&cpu_load)) {
		log_message(LOG_INFO, "%s(): Error initializing CPU monitoring (%m)"
				    , __FUNCTION__);
		return -1;
	}

	percpu_metrics = calloc(cpu_load->nr_cpus, sizeof(*percpu_metrics));
	if (!percpu_metrics) {
		cpu_load_destroy(cpu_load);
		return -1;
	}

	thread_add_event(master, fswan_cpu_poll, NULL, 0);
	return 0;
}

int
fswan_cpu_destroy(void)
{
	cpu_load_destroy(cpu_load);
	free(percpu_metrics);
	percpu_metrics = NULL;
	return 0;
}
