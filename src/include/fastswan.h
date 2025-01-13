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

#ifndef _FASTSWAN_H
#define _FASTSWAN_H

#include <net/ethernet.h>
#include <net/if.h>

#include "daemon.h"
#include "memory.h"
#include "bitops.h"
#include "utils.h"
#include "pidfile.h"
#include "signals.h"
#include "timer.h"
#include "timer_thread.h"
#include "scheduler.h"
#include "vector.h"
#include "command.h"
#include "rbtree.h"
#include "vty.h"
#include "logger.h"
#include "list_head.h"
#include "json_reader.h"
#include "json_writer.h"
#include "pkt_buffer.h"
#include "jhash.h"
#include "fswan_if.h"
#include "fswan_netlink.h"
#include "fswan_data.h"
#include "fswan_vty.h"
#include "fswan_bpf.h"
#include "fswan_bpf_vty.h"
#include "fswan_bpf_xfrm.h"

#endif
