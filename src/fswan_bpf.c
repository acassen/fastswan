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

/* system includes */
#include <errno.h>
#include <stdarg.h>
#include <libbpf.h>

/* local includes */
#include "logger.h"
#include "utils.h"
#include "fswan_bpf.h"
#include "fswan_bpf_prog.h"


/*
 *	libbpf print bridge
 */
static int
fswan_bpf_log_message(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !(debug & 16))
		return 0;

	log_message(LOG_INFO, format, args);
	return 0;
}


/*
 *	BPF MAP helpers (used by per-feature wiring like fswan_bpf_xfrm)
 */
struct bpf_map *
fswan_bpf_load_map(struct bpf_object *obj, const char *map_name)
{
	struct bpf_map *map;
	char errmsg[FSWAN_XDP_STRERR_BUFSIZE];

	map = bpf_object__find_map_by_name(obj, map_name);
	if (!map) {
		libbpf_strerror(errno, errmsg, sizeof(errmsg));
		log_message(LOG_INFO, "%s(): BPF: error mapping tab:%s err:%d (%s)"
				    , __FUNCTION__, map_name, errno, errmsg);
		return NULL;
	}

	return map;
}

int
fswan_bpf_map_load(struct fswan_bpf_prog *p, const char *map_str, int map_idx)
{
	struct bpf_map *map;

	if (!p)
		return -1;

	map = fswan_bpf_load_map(p->bpf_obj, map_str);
	if (!map) {
		log_message(LOG_INFO, "%s(): Unable to load map '%s' from bpf-program '%s'"
				    , __FUNCTION__, map_str, p->name);
		return -1;
	}

	p->bpf_maps[map_idx].map = map;
	return 0;
}


/*
 *	BPF service init
 */
int
fswan_bpf_init(void)
{
	libbpf_set_print(fswan_bpf_log_message);
	return 0;
}

int
fswan_bpf_destroy(void)
{
	fswan_bpf_prog_destroy_all();
	return 0;
}
