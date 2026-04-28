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
#include "logger.h"
#include "thread.h"
#include "fswan_if.h"
#include "fswan_if_ethtool.h"
#include "fswan_cpu.h"
#include "fswan_monitor.h"

/* Local data */
static int ethtool_tick;

/* Extern data */
extern struct thread_master *master;


/*
 *	Polling thread
 */
static void
fswan_monitor_poll(__attribute__((unused)) struct thread *t)
{
	struct timespec ts;
	uint64_t now_ns;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	now_ns = timespec_to_ns(&ts);

	fswan_percpu_reset();

	if (++ethtool_tick >= ETHTOOL_POLL_TICKS) {
		ethtool_tick = 0;
		fswan_if_foreach(fswan_if_collect, &now_ns);
		fswan_percpu_collect_all();

		/* Re-read clock to exclude syscall latency from rate calc. */
		clock_gettime(CLOCK_MONOTONIC, &ts);
		now_ns = timespec_to_ns(&ts);
		fswan_percpu_rates_update(now_ns);
	}

	fswan_percpu_load_update_all();

	thread_add_timer(master, fswan_monitor_poll, NULL, TIMER_HZ / 5);
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

	thread_add_event(master, fswan_monitor_poll, NULL, 0);
	return 0;
}

int
fswan_monitor_destroy(void)
{
	fswan_percpu_destroy();
	return 0;
}
