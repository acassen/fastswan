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

#include <sched.h>
#include <sys/resource.h>

#define	RT_RLIMIT_DEFAULT	10000

/* The maximum pid is 2^22 - see definition of PID_MAX_LIMIT in kernel source include/linux/threads.h */
#define PID_MAX_DIGITS		7

extern long min_auto_priority_delay;

int process_lock_memory(void);
int process_unlock_memory(void);
void set_process_priorities(int realtime_priority, int max_realtime_priority, long min_delay,
			    int rlimit_rt, int process_priority, int no_swap_stack_size);

void reset_process_priorities(void);
void increment_process_priority(void);
unsigned get_cur_priority(void) __attribute__((pure));
unsigned get_cur_rlimit_rttime(void) __attribute__((pure));
int set_process_cpu_affinity(cpu_set_t *, const char *);
int get_process_cpu_affinity_string(cpu_set_t *set, char *buffer, size_t size);
void set_child_rlimit(int resource, const struct rlimit *rlim);

void set_max_file_limit(unsigned fd_required);
