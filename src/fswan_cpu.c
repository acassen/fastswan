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
#include "logger.h"
#include "utils.h"
#include "bitops.h"
#include "cpu.h"
#include "gauge.h"
#include "ethtool.h"
#include "fswan_data.h"
#include "fswan_if.h"
#include "fswan_if_ethtool.h"
#include "fswan_if_rxq.h"
#include "fswan_cpu.h"

/* Local data */
struct cpu_load *cpu_load;
/* double-buffer: poll thread writes to percpu_back, then flips percpu_front.
 * Readers acquire percpu_front atomically. */
static struct fswan_percpu_metrics *percpu_back;
static struct fswan_percpu_metrics *percpu_front;
static uint64_t percpu_prev_ts_ns;

/* Extern data */
extern struct data *daemon_data;


bool
fswan_cpu_active(int cpu)
{
	if (!__test_bit(FSWAN_FL_CPU_MASK_BIT, &daemon_data->flags))
		return true;
	return CPU_ISSET(cpu, &daemon_data->cpu_mask);
}

/* Suppress the rate spike a freshly-activated CPU would emit on next tick. */
void
fswan_percpu_baseline_reset(void)
{
	percpu_prev_ts_ns = 0;
}


/*
 *	Per-CPU workload aggregation
 *
 * Fetch ethtool stats for one interface and accumulate per-queue counters
 * into the per-CPU back buffer, using IRQ affinity to map {queue,cpu}.
 */
static int
fswan_iface_sample(struct interface *iface, void *arg)
{
	int cpu_per_q[iface->nr_rx_queues ? : 1];
	uint32_t q, nr;
	int cpu;

	if (__test_bit(FSWAN_INTERFACE_FL_DESTROYING_BIT, &iface->flags))
		return 0;
	if (!iface->queue_stats)
		return 0;
	if (fswan_if_collect_ethtool(iface, *(uint64_t *)arg) < 0)
		return 0;

	nr = max(iface->nr_rx_queues, iface->nr_tx_queues);
	memset(cpu_per_q, -1, sizeof(cpu_per_q));
	fswan_if_rxq_cpu(iface, cpu_per_q, iface->nr_rx_queues);

	for (q = 0; q < nr; q++) {
		struct ethtool_q_stats *s = &iface->queue_stats[q];

		cpu = (q < iface->nr_rx_queues) ? cpu_per_q[q] : -1;
		if (cpu < 0 || cpu >= cpu_load->nr_cpus || !fswan_cpu_active(cpu))
			continue;
		ethtool_q_stats_add(&percpu_back[cpu].q_stats, s);
	}
	return 0;
}

const struct fswan_percpu_metrics *
fswan_percpu_metrics_get(int cpu)
{
	struct fswan_percpu_metrics *m;

	m = __atomic_load_n(&percpu_front, __ATOMIC_ACQUIRE);
	if (!m || cpu < 0 || cpu >= cpu_load->nr_cpus)
		return NULL;
	return &m[cpu];
}

void
fswan_percpu_sample_all(uint64_t now_ns)
{
	int i;

	for (i = 0; i < cpu_load->nr_cpus; i++)
		memset(&percpu_back[i].q_stats, 0, sizeof(percpu_back[i].q_stats));
	fswan_if_foreach(fswan_iface_sample, &now_ns);
}

static inline void
ewma_update(double *ewma, double cur)
{
	*ewma = EWMA_DEFAULT_ALPHA * cur + (1.0 - EWMA_DEFAULT_ALPHA) * *ewma;
}

static inline uint64_t
delta_rate(uint64_t cur, uint64_t prev, uint64_t elapsed)
{
	return (cur - prev) * NSEC_PER_SEC / elapsed;
}

void
fswan_percpu_rates_update(uint64_t now_ns)
{
	uint64_t elapsed = now_ns - percpu_prev_ts_ns;
	struct ethtool_q_stats *q, *p;
	struct fswan_percpu_metrics *m;
	int i;

	for (i = 0; i < cpu_load->nr_cpus; i++) {
		if (!fswan_cpu_active(i))
			continue;
		m = &percpu_back[i];
		q = &m->q_stats;
		p = &m->prev_q_stats;

		if (elapsed && percpu_prev_ts_ns) {
			m->rx.bw_bps = delta_rate(q->rx_bytes, p->rx_bytes, elapsed);
			m->tx.bw_bps = delta_rate(q->tx_bytes, p->tx_bytes, elapsed);
			m->rx.pps = delta_rate(q->rx_packets, p->rx_packets, elapsed);
			m->tx.pps = delta_rate(q->tx_packets, p->tx_packets, elapsed);
			m->total_bw_bps = m->rx.bw_bps + m->tx.bw_bps;
			m->rx_buff_alloc_err_rate = delta_rate(q->rx_buff_alloc_err,
							       p->rx_buff_alloc_err,
							       elapsed);
		}
		ewma_update(&m->rx.bw_bps_ewma, m->rx.bw_bps);
		ewma_update(&m->tx.bw_bps_ewma, m->tx.bw_bps);
		ewma_update(&m->total_bw_bps_ewma, m->total_bw_bps);
		ewma_update(&m->rx.pps_ewma, m->rx.pps);
		ewma_update(&m->tx.pps_ewma, m->tx.pps);

		gauge_history_push(&m->bw_history, (float) m->total_bw_bps);
		gauge_history_push(&m->pps_history, (float) (m->rx.pps + m->tx.pps));

		*p = *q;
	}
	percpu_prev_ts_ns = now_ns;
}

void
fswan_percpu_load_update_all(void)
{
	struct fswan_percpu_metrics *m;
	float load;
	int i;

	cpu_load_update(cpu_load);
	for (i = 0; i < cpu_load->nr_cpus; i++) {
		if (!fswan_cpu_active(i))
			continue;
		m = &percpu_back[i];

		load = cpu_load_get(cpu_load, i);
		if (load < 0.0f)
			continue;
		gauge_history_push(&m->load_history, load);
		m->load = load;
		m->load_ewma = EWMA_DEFAULT_ALPHA * load
			     + (1.0f - EWMA_DEFAULT_ALPHA) * m->load_ewma;
	}
}

void
fswan_percpu_publish(void)
{
	struct fswan_percpu_metrics *tmp;

	tmp = __atomic_exchange_n(&percpu_front, percpu_back, __ATOMIC_RELEASE);
	percpu_back = tmp;
}


/*
 *	Init / destroy
 */
int
fswan_percpu_init(void)
{
	if (cpu_load_init_tsc(&cpu_load)) {
		log_message(LOG_INFO, "%s(): Error initializing CPU monitoring (%m)"
				    , __FUNCTION__);
		return -1;
	}

	percpu_front = calloc(cpu_load->nr_cpus, sizeof(*percpu_front));
	if (!percpu_front) {
		cpu_load_destroy(cpu_load);
		return -1;
	}

	percpu_back = calloc(cpu_load->nr_cpus, sizeof(*percpu_back));
	if (!percpu_back) {
		free(percpu_front);
		cpu_load_destroy(cpu_load);
		return -1;
	}
	return 0;
}

void
fswan_percpu_destroy(void)
{
	cpu_load_destroy(cpu_load);
	free(percpu_front);
	percpu_front = NULL;
	free(percpu_back);
	percpu_back = NULL;
}
