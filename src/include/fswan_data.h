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

#ifndef _FSWAN_DATA_H
#define _FSWAN_DATA_H

/* Default values */
#define FSWAN_STR_MAX_LEN	128
#define FSWAN_PATH_MAX_LEN	128
#define FSWAN_NAME_MAX_LEN	64

/* Flags */
enum daemon_flags {
	FSWAN_FL_STOP_BIT,
	FSWAN_FL_XFRM_KERNEL_LOADED_BIT,
	FSWAN_FL_XDP_XFRM_LOADED_BIT,
};

/* Main control block */
typedef struct _data {
	list_head_t		bpf_progs;
	list_head_t		interfaces;
	unsigned		nl_rcvbuf_size;

	unsigned long		flags;
} data_t;

/* Prototypes */
extern data_t *alloc_daemon_data(void);
extern void free_daemon_data(void);

#endif
