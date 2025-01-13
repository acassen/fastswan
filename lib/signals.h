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

#ifndef _SIGNALS_H
#define _SIGNALS_H

#include "config.h"

#include <signal.h>
#include <stdbool.h>

#include "scheduler.h"

#define SIGJSON 		(SIGRTMIN + 2)
#ifdef THREAD_DUMP
#define	SIGTDUMP		(SIGRTMAX)
#endif
#define	SIGSTATS_CLEAR		(SIGRTMAX - 1)
#ifndef _ONE_PROCESS_DEBUG_
#endif

static inline int
sigmask_func(int how, const sigset_t *set, sigset_t *oldset)
{
#ifdef _WITH_PTHREADS_
    return pthread_sigmask(how, set, oldset);
#else
    return sigprocmask(how, set, oldset);
#endif
}

/* Prototypes */
extern int get_signum(const char *);
extern void signal_set(int, void (*) (void *, int), void *);
extern void signal_ignore(int);
extern int signal_handler_init(void);
extern void signal_handler_destroy(void);
extern void signal_handler_script(void);
extern void add_signal_read_thread(thread_master_t *);
extern void cancel_signal_read_thread(void);
extern void set_sigxcpu_handler(void);
extern void signal_noignore_sigchld(void);
extern void signal_noignore_sig(int);

#ifdef THREAD_DUMP
extern void register_signal_thread_addresses(void);
#endif

#endif
