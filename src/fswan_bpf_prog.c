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
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <linux/if_link.h>
#include <libbpf.h>

/* local includes */
#include "memory.h"
#include "logger.h"
#include "bitops.h"
#include "list_head.h"
#include "fswan_data.h"
#include "fswan_if.h"
#include "fswan_bpf.h"
#include "fswan_bpf_prog.h"
#include "fswan_bpf_xfrm.h"


/* Local data */
static const char *pin_basedir = "/sys/fs/bpf";


/* Extern data */
extern struct data *daemon_data;


/*
 *	Lookup / allocation
 */
struct fswan_bpf_prog *
fswan_bpf_prog_get(const char *name)
{
	struct fswan_bpf_prog *p;

	list_for_each_entry(p, &daemon_data->bpf_progs, next) {
		if (!strcmp(p->name, name))
			return p;
	}
	return NULL;
}

struct fswan_bpf_prog *
fswan_bpf_prog_alloc(const char *name)
{
	struct fswan_bpf_prog *new;

	PMALLOC(new);
	strlcpy(new->name, name, FSWAN_STR_MAX_LEN - 1);
	INIT_LIST_HEAD(&new->iface_bind_list);
	INIT_LIST_HEAD(&new->next);
	__set_bit(FSWAN_BPF_PROG_FL_SHUTDOWN_BIT, &new->flags);

	list_add_tail(&new->next, &daemon_data->bpf_progs);
	return new;
}


/*
 *	Helpers
 */
static int
fswan_bpf_prog_any_loaded(void)
{
	struct fswan_bpf_prog *p;

	list_for_each_entry(p, &daemon_data->bpf_progs, next)
		if (!__test_bit(FSWAN_BPF_PROG_FL_SHUTDOWN_BIT, &p->flags))
			return 1;
	return 0;
}


/*
 *	BPF object load helpers
 */
static void
fswan_bpf_prog_cleanup_pinned_maps(struct fswan_bpf_prog *p)
{
	char errmsg[FSWAN_XDP_STRERR_BUFSIZE];
	struct bpf_map *map;
	char buf[FSWAN_PATH_MAX_LEN];
	int len, err;

	bpf_object__for_each_map(map, p->bpf_obj) {
		len = snprintf(buf, sizeof(buf), "%s/%s/%s"
					      , pin_basedir, p->name
					      , bpf_map__name(map));
		if (len < 0 || (size_t)len >= sizeof(buf))
			continue;

		if (access(buf, F_OK) != 0)
			continue;

		err = bpf_map__unpin(map, buf);
		if (err) {
			libbpf_strerror(err, errmsg, sizeof(errmsg));
			log_message(LOG_INFO, "%s(): unpin %s err:%d (%s)"
					    , __FUNCTION__, buf, err, errmsg);
		}
	}
}

static struct bpf_program *
fswan_bpf_prog_lookup_program(struct fswan_bpf_prog *p)
{
	struct bpf_program *prog;

	if (p->progname[0]) {
		prog = bpf_object__find_program_by_name(p->bpf_obj, p->progname);
		if (prog)
			return prog;
		log_message(LOG_INFO, "%s(): unknown program '%s' in %s, falling back"
				    , __FUNCTION__, p->progname, p->path);
	}

	return bpf_object__next_program(p->bpf_obj, NULL);
}


/*
 *	Lazy load: open + verify + xfrm map wiring.
 */
int
fswan_bpf_prog_load(struct fswan_bpf_prog *p)
{
	char errmsg[FSWAN_XDP_STRERR_BUFSIZE];
	int err;

	if (!__test_bit(FSWAN_BPF_PROG_FL_SHUTDOWN_BIT, &p->flags))
		return 0;

	if (!p->path[0]) {
		log_message(LOG_INFO, "bpf-program '%s': missing path", p->name);
		__set_bit(FSWAN_BPF_PROG_FL_LOAD_ERR_BIT, &p->flags);
		return -1;
	}

	p->bpf_obj = bpf_object__open(p->path);
	if (!p->bpf_obj) {
		libbpf_strerror(errno, errmsg, sizeof(errmsg));
		log_message(LOG_INFO, "bpf-program '%s': open(%s) err:%d (%s)"
				    , p->name, p->path, errno, errmsg);
		__set_bit(FSWAN_BPF_PROG_FL_LOAD_ERR_BIT, &p->flags);
		return -1;
	}

	fswan_bpf_prog_cleanup_pinned_maps(p);

	err = bpf_object__load(p->bpf_obj);
	if (err) {
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		log_message(LOG_INFO, "bpf-program '%s': load err:%d (%s)"
				    , p->name, err, errmsg);
		bpf_object__close(p->bpf_obj);
		p->bpf_obj = NULL;
		__set_bit(FSWAN_BPF_PROG_FL_LOAD_ERR_BIT, &p->flags);
		return -1;
	}

	if (fswan_bpf_xfrm_map_load(p)) {
		bpf_object__close(p->bpf_obj);
		p->bpf_obj = NULL;
		__set_bit(FSWAN_BPF_PROG_FL_LOAD_ERR_BIT, &p->flags);
		return -1;
	}

	__clear_bit(FSWAN_BPF_PROG_FL_SHUTDOWN_BIT, &p->flags);
	__clear_bit(FSWAN_BPF_PROG_FL_LOAD_ERR_BIT, &p->flags);
	__set_bit(FSWAN_FL_XDP_XFRM_LOADED_BIT, &daemon_data->flags);
	log_message(LOG_INFO, "bpf-program '%s': loaded from %s", p->name, p->path);
	return 0;
}

void
fswan_bpf_prog_unload(struct fswan_bpf_prog *p)
{
	struct interface *iface, *tmp;

	if (__test_bit(FSWAN_BPF_PROG_FL_SHUTDOWN_BIT, &p->flags))
		return;

	/* Detach every still-bound interface first. */
	list_for_each_entry_safe(iface, tmp, &p->iface_bind_list, bpf_prog_list)
		fswan_bpf_prog_detach(p, iface);

	if (p->bpf_maps)
		FREE(p->bpf_maps);

	if (p->bpf_obj) {
		bpf_object__close(p->bpf_obj);
		p->bpf_obj = NULL;
	}

	__set_bit(FSWAN_BPF_PROG_FL_SHUTDOWN_BIT, &p->flags);
	if (!fswan_bpf_prog_any_loaded())
		__clear_bit(FSWAN_FL_XDP_XFRM_LOADED_BIT, &daemon_data->flags);
	log_message(LOG_INFO, "bpf-program '%s': unloaded", p->name);
}


/*
 *	Attach / detach an interface to a (possibly not-yet-loaded) program.
 */
int
fswan_bpf_prog_attach(struct fswan_bpf_prog *p, struct interface *iface)
{
	struct bpf_program *bpf_prog;
	char errmsg[FSWAN_XDP_STRERR_BUFSIZE];
	int err;

	/* Lazy-load on first attach if needed. */
	if (__test_bit(FSWAN_BPF_PROG_FL_SHUTDOWN_BIT, &p->flags) &&
	    fswan_bpf_prog_load(p))
		return -1;

	if (iface->bpf_xdp_lnk)
		return 0;

	bpf_prog = fswan_bpf_prog_lookup_program(p);
	if (!bpf_prog) {
		log_message(LOG_INFO, "bpf-program '%s': no XDP program found in %s"
				    , p->name, p->path);
		return -1;
	}

	/* Detach any stalled XDP program left by a previous run. */
	err = bpf_xdp_detach(iface->ifindex, XDP_FLAGS_DRV_MODE, NULL);
	if (err) {
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		log_message(LOG_INFO, "interface %s: stale XDP detach (%s)"
				    , iface->ifname, errmsg);
	}

	iface->bpf_xdp_lnk = bpf_program__attach_xdp(bpf_prog, iface->ifindex);
	if (!iface->bpf_xdp_lnk) {
		libbpf_strerror(errno, errmsg, sizeof(errmsg));
		log_message(LOG_INFO, "bpf-program '%s': attach to %s err:%d (%s)"
				    , p->name, iface->ifname, errno, errmsg);
		return -1;
	}

	if (fswan_bpf_xfrm_stats_iface_register(p, iface)) {
		bpf_link__destroy(iface->bpf_xdp_lnk);
		iface->bpf_xdp_lnk = NULL;
		return -1;
	}

	__set_bit(FSWAN_INTERFACE_FL_RUNNING_BIT, &iface->flags);
	log_message(LOG_INFO, "bpf-program '%s': attached to %s (ifindex:%d)"
			    , p->name, iface->ifname, iface->ifindex);
	return 0;
}

void
fswan_bpf_prog_detach(struct fswan_bpf_prog *p, struct interface *iface)
{
	if (!iface->bpf_xdp_lnk)
		return;

	bpf_link__destroy(iface->bpf_xdp_lnk);
	iface->bpf_xdp_lnk = NULL;
	fswan_bpf_xfrm_stats_iface_unregister(p, iface);
	__clear_bit(FSWAN_INTERFACE_FL_RUNNING_BIT, &iface->flags);

	log_message(LOG_INFO, "bpf-program '%s': detached from %s"
			    , p->name, iface->ifname);
}


/*
 *	Final teardown.
 */
void
fswan_bpf_prog_destroy(struct fswan_bpf_prog *p)
{
	struct interface *iface, *tmp;

	list_for_each_entry_safe(iface, tmp, &p->iface_bind_list, bpf_prog_list) {
		fswan_bpf_prog_detach(p, iface);
		list_head_del(&iface->bpf_prog_list);
		iface->bpf_prog = NULL;
	}

	fswan_bpf_prog_unload(p);
	list_head_del(&p->next);
	FREE(p);
}

void
fswan_bpf_prog_destroy_all(void)
{
	struct fswan_bpf_prog *p, *tmp;

	list_for_each_entry_safe(p, tmp, &daemon_data->bpf_progs, next)
		fswan_bpf_prog_destroy(p);
}
