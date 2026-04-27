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

#include <signal.h>
#include <stdbool.h>
#include "thread.h"

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
int get_signum(const char *sigfunc);
void signal_set(int signo, void (*func) (void *, int), void *v);
void signal_ignore(int signo);
int signal_handler_init(void);
void signal_handler_destroy(void);
void signal_handler_script(void);
void add_signal_read_thread(struct thread_master *m);
void cancel_signal_read_thread(void);
void set_sigxcpu_handler(void);
void signal_noignore_sigchld(void);
void signal_noignore_sig(int sig);
