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

#ifndef _TIMER_THREAD_H
#define _TIMER_THREAD_H

enum {
	TIMER_THREAD_FL_STOP_BIT,
};

#define TIMER_THREAD_NAMESIZ	128
typedef struct _timer_thread {
	char			name[TIMER_THREAD_NAMESIZ];
	rb_root_cached_t	timer;
	pthread_mutex_t		timer_mutex;
	pthread_t		task;
	pthread_cond_t		cond;
	pthread_mutex_t		cond_mutex;
	int			(*fired) (void *);

	unsigned long		flags;
} timer_thread_t;

typedef struct _timer_node {
	int		(*to_func) (void *);
	void		*to_arg;
	timeval_t	sands;
	rb_node_t	n;
} timer_node_t;


/* prototypes */
extern void timer_node_expire_now(timer_thread_t *, timer_node_t *);
extern void timer_node_init(timer_node_t *, int (*fn) (void *), void *);
extern void timer_node_add(timer_thread_t *, timer_node_t *, int);
extern int timer_node_pending(timer_node_t *);
extern int timer_node_del(timer_thread_t *, timer_node_t *);
extern int timer_thread_init(timer_thread_t *, const char *, int (*fired) (void *));
extern int timer_thread_signal(timer_thread_t *);
extern int timer_thread_destroy(timer_thread_t *);

#endif
