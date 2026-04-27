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

#include <libbpf.h>

#include "fswan_bpf_prog.h"

/* defines */
#define FSWAN_XDP_STRERR_BUFSIZE	(1 << 7)
#define XDP_PATH_MAX			(1 << 7)


/* Prototypes */
int fswan_bpf_map_load(struct fswan_bpf_prog *p, const char *map_str, int map_idx);
struct bpf_map *fswan_bpf_load_map(struct bpf_object *obj, const char *map_name);
int fswan_bpf_init(void);
int fswan_bpf_destroy(void);
