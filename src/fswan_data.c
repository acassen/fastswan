/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Soft:        The main goal of this project is to provide a fast data-path
 *              for the Linux Kernel XFRM layer. Some NIC vendors offer IPSEC
 *              acceleration via a Crypto mode or a Packet mode. In Packet
 *              mode, all IPSEC ESP operations are done by the hardware to
 *              offload the kernel for crypto and packet handling. To further
 *              increase perfs we implement kernel routing offload via XDP.
 *              A XFRM kernel netlink reflector is dynamically andi
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
 * Copyright (C) 2025 Alexandre Cassen, <acassen@gmail.com>
 */

/* system includes */
#include <pthread.h>
#include <sys/stat.h>
#include <net/if.h>

/* local includes */
#include "fastswan.h"


/* Extern data */
extern data_t *daemon_data;


/*
 *	Daemon Control Block helpers
 */
data_t *
alloc_daemon_data(void)
{
	data_t *new;

	fswan_bpf_init();

	PMALLOC(new);
	INIT_LIST_HEAD(&new->bpf_progs);
	INIT_LIST_HEAD(&new->interfaces);

	return new;
}

void
free_daemon_data(void)
{
	fswan_netlink_destroy();
	fswan_bpf_destroy();
	FREE(daemon_data);
}

