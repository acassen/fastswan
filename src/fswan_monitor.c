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

#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include "logger.h"
#include "timer.h"
#include "fswan_cpu.h"
#include "fswan_monitor.h"

#define MONITOR_POLL_NS		200000000ULL	/* 200 ms poll interval in nanoseconds */
#define ETHTOOL_POLL_TICKS	15		/* 3 seconds at 5 Hz polling */

/* Local data */
static pthread_t poll_thread;
static volatile int poll_stop;
static volatile int poll_foreach_active;
static int poll_thread_running;


/*
 *	Interface quiesce: spin until the poll thread is not walking the
 *	interface list. Called by fswan_if_destroy() before list_del()/free().
 */
void
fswan_monitor_iface_quiesce(void)
{
	if (!poll_thread_running)
		return;
	while (__sync_fetch_and_add(&poll_foreach_active, 0))
		usleep(1000);
}


/*
 *	Polling thread
 */
static void *
fswan_monitor_poll_thread(__attribute__((unused)) void *arg)
{
	struct timespec next;
	static int ethtool_tick;
	uint64_t now_ns;

	clock_gettime(CLOCK_MONOTONIC, &next);

	for (;;) {
		timespec_add_ns(&next, MONITOR_POLL_NS);
		clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &next, NULL);

		if (poll_stop)
			break;

		if (++ethtool_tick >= ETHTOOL_POLL_TICKS) {
			now_ns = clock_gettime_ns(CLOCK_MONOTONIC);
			ethtool_tick = 0;

			__sync_add_and_fetch(&poll_foreach_active, 1);
			fswan_percpu_sample_all(now_ns);
			__sync_sub_and_fetch(&poll_foreach_active, 1);

			/* Re-read clock to exclude collection latency
			 * from rate calc */
			now_ns = clock_gettime_ns(CLOCK_MONOTONIC);
			fswan_percpu_rates_update(now_ns);
		}

		fswan_percpu_load_update_all();
		fswan_percpu_publish();
	}

	return NULL;
}


/*
 *	Pin the poll thread to a CPU set
 */
int
fswan_monitor_set_cpu_affinity(const cpu_set_t *set)
{
	if (!poll_thread_running)
		return 0;
	if (pthread_setaffinity_np(poll_thread, sizeof(*set), set)) {
		log_message(LOG_WARNING, "%s(): unable to set monitor pthread affinity (%m)"
				       , __FUNCTION__);
		return -1;
	}
	return 0;
}


/*
 *	Init / destroy
 */
int
fswan_monitor_init(void)
{
	if (fswan_percpu_init()) {
		log_message(LOG_INFO, "%s(): Error initializing CPU monitoring (%m)"
				    , __FUNCTION__);
		return -1;
	}

	if (pthread_create(&poll_thread, NULL, fswan_monitor_poll_thread, NULL)) {
		log_message(LOG_INFO, "%s(): Error creating poll thread (%m)"
				    , __FUNCTION__);
		fswan_percpu_destroy();
		return -1;
	}
	poll_thread_running = 1;
	return 0;
}

int
fswan_monitor_destroy(void)
{
	if (poll_thread_running) {
		poll_stop = 1;
		pthread_join(poll_thread, NULL);
		poll_thread_running = 0;
	}
	fswan_percpu_destroy();
	return 0;
}
