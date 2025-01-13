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

#ifndef _FSWAN_IF_H
#define _FSWAN_IF_H

#include <net/if.h>

/* Defines */
#define IF_DEFAULT_CONNECTION_KEEPIDLE		20
#define IF_DEFAULT_CONNECTION_KEEPCNT		2
#define IF_DEFAULT_CONNECTION_KEEPINTVL		10

/* Types */
typedef struct _interface {
	char		ifname[IF_NAMESIZE];
	int		ifindex;

	/* statistics */
	uint64_t	rx_pkts;
	uint64_t	rx_bytes;
	uint64_t	tx_pkts;
	uint64_t	tx_bytes;

	list_head_t	next;
} interface_t;


/* Prototypes */
extern int if_setsockopt_reuseaddr(int, int);
extern int if_setsockopt_nolinger(int, int);
extern int if_setsockopt_tcpcork(int, int);
extern int if_setsockopt_nodelay(int, int);
extern int if_setsockopt_keepalive(int, int);
extern int if_setsockopt_tcp_keepidle(int, int);
extern int if_setsockopt_tcp_keepcnt(int, int);
extern int if_setsockopt_tcp_keepintvl(int, int);
extern int if_setsockopt_rcvtimeo(int, int);
extern int if_setsockopt_sndtimeo(int, int);
extern int if_setsockopt_reuseport(int, int);
extern int if_setsockopt_hdrincl(int);
extern int if_setsockopt_broadcast(int);
extern int if_setsockopt_promisc(int, int, bool);
extern int if_setsockopt_attach_bpf(int, int);
extern int if_setsockopt_no_receive(int *);
extern int if_setsockopt_rcvbuf(int *, int);
extern int if_setsockopt_bindtodevice(int *, const char *);
extern int if_setsockopt_priority(int *, int);
extern int if_nametohwaddr(const char *, unsigned char *, size_t);

#endif
