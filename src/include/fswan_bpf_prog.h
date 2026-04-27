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

#include "list_head.h"
#include "fswan_data.h"

/* Forward declarations */
struct interface;

/* BPF MAP wrapper */
struct fswan_bpf_maps {
	struct bpf_map		*map;
};

/* Per-program flags */
enum fswan_bpf_prog_flags {
	FSWAN_BPF_PROG_FL_SHUTDOWN_BIT,
	FSWAN_BPF_PROG_FL_LOAD_ERR_BIT,
};

/* A declared BPF program. Lifecycle:
 *   declare -> SHUTDOWN_BIT set, no kernel state.
 *   load    -> bpf_object__open + load + map wiring; SHUTDOWN_BIT cleared.
 *   attach  -> per-interface bpf_program__attach_xdp; iface linked into
 *              iface_bind_list.
 */
struct fswan_bpf_prog {
	char			name[FSWAN_STR_MAX_LEN];
	char			description[FSWAN_STR_MAX_LEN];
	char			path[FSWAN_PATH_MAX_LEN];
	char			progname[FSWAN_STR_MAX_LEN];
	char			pin_root_path[FSWAN_STR_MAX_LEN];
	struct bpf_object	*bpf_obj;
	struct fswan_bpf_maps	*bpf_maps;
	struct list_head	iface_bind_list;	/* attached interfaces */
	struct list_head	next;			/* in daemon_data->bpf_progs */
	unsigned long		flags;
};


/* Prototypes */
struct fswan_bpf_prog *fswan_bpf_prog_alloc(const char *name);
struct fswan_bpf_prog *fswan_bpf_prog_get(const char *name);
int fswan_bpf_prog_load(struct fswan_bpf_prog *p);
void fswan_bpf_prog_unload(struct fswan_bpf_prog *p);
int fswan_bpf_prog_attach(struct fswan_bpf_prog *p, struct interface *iface);
void fswan_bpf_prog_detach(struct fswan_bpf_prog *p, struct interface *iface);
void fswan_bpf_prog_destroy(struct fswan_bpf_prog *p);
void fswan_bpf_prog_destroy_all(void);
