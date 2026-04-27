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
#pragma once

#include <libbpf.h>

#include "list_head.h"
#include "vty.h"
#include "fswan_data.h"

/* defines */
#define FSWAN_XDP_STRERR_BUFSIZE	(1 << 7)
#define XDP_PATH_MAX			(1 << 7)

enum fswan_bpf_prog_type {
	BPF_PROG_QDISC = 0,
	BPF_PROG_XDP,
};


/* BPF related */
struct fswan_bpf_maps {
	struct bpf_map		*map;
};

struct fswan_bpf_opts {
	char			label[FSWAN_STR_MAX_LEN];
	int			type;
	char			filename[FSWAN_STR_MAX_LEN];
	char			progname[FSWAN_STR_MAX_LEN];
	int			ifindex;
	char			pin_root_path[FSWAN_STR_MAX_LEN];
	struct bpf_object	*bpf_obj;
	struct bpf_link		*bpf_lnk;
	struct fswan_bpf_maps	*bpf_maps;
	struct vty		*vty;

	void (*bpf_unload) (struct fswan_bpf_opts *);

	struct list_head	next;
};


/* Prototypes */
extern int fswan_bpf_map_load(struct fswan_bpf_opts *, const char *, int);
extern struct bpf_map *fswan_bpf_load_map(struct bpf_object *, const char *);
extern struct fswan_bpf_opts *fswan_bpf_opts_alloc(int, void (*bpf_unload) (struct fswan_bpf_opts *));
extern int fswan_bpf_opts_add(struct fswan_bpf_opts *, struct list_head *);
extern int fswan_bpf_opts_del(struct fswan_bpf_opts *);
extern struct fswan_bpf_opts *fswan_bpf_opts_exist(struct list_head *, int, const char **);
extern struct fswan_bpf_opts *fswan_bpf_opts_get_by_label(struct list_head *, const char *);
extern void fswan_bpf_opts_destroy(struct list_head *);
extern int fswan_bpf_opts_load(struct fswan_bpf_opts *, struct vty *, int, const char **,
			     int (*bpf_load) (struct fswan_bpf_opts *));
extern int fswan_xdp_load(struct fswan_bpf_opts *);
extern void fswan_xdp_unload(struct fswan_bpf_opts *);
extern int fswan_bpf_init(void);
extern int fswan_bpf_destroy(void);
