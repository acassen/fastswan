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

/* system includes */
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <errno.h>
#include <libbpf.h>

/* local includes */
#include "fastswan.h"

/* Local data */
static const char *pin_basedir = "/sys/fs/bpf";


/* Extern data */
extern data_t *daemon_data;

/*
 *	BPF MAP related
 */
int
fswan_bpf_map_load(fswan_bpf_opts_t *opts, const char *map_str, int map_idx)
{
	struct bpf_map *map;

	if (!opts)
		return -1;

	map = fswan_bpf_load_map(opts->bpf_obj, map_str);
	if (!map) {
		log_message(LOG_INFO, "%s(): Unable to load map '%s' from bpf_prog '%s'"
				    , __FUNCTION__
				    , map_str, opts->filename);
		return -1;
	}

	opts->bpf_maps[map_idx].map = map;
	return 0;
}

int
fswan_bpf_map_unload(fswan_bpf_opts_t *opts)
{
	if (opts->bpf_maps)
		FREE(opts->bpf_maps);
	return 0;
}

/*
 *	BPF opts related
 */
fswan_bpf_opts_t *
fswan_bpf_opts_alloc(int type, void (*bpf_unload) (fswan_bpf_opts_t *))
{
	fswan_bpf_opts_t *new;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->next);
	new->type = type;
	new->bpf_unload = bpf_unload;

	return new;
}

int
fswan_bpf_opts_add(fswan_bpf_opts_t *opts, list_head_t *l)
{
	list_add_tail(&opts->next, l);
	return 0;
}

int
fswan_bpf_opts_del(fswan_bpf_opts_t *opts)
{
	if (opts->bpf_unload)
		(*opts->bpf_unload) (opts);
	list_head_del(&opts->next);
	fswan_bpf_map_unload(opts);
	FREE(opts);
	return 0;
}

fswan_bpf_opts_t *
fswan_bpf_opts_exist(list_head_t *l, int argc, const char **argv)
{
	fswan_bpf_opts_t *opts;
	int ifindex;

	if (argc < 2)
		return NULL;

	ifindex = if_nametoindex(argv[2]);
	if (!ifindex)
		return NULL;

	list_for_each_entry(opts, l, next) {
		if (opts->ifindex == ifindex &&
		    !strncmp(opts->filename, argv[1], FSWAN_STR_MAX_LEN))
			return opts;
	}

	return NULL;
}

fswan_bpf_opts_t *
fswan_bpf_opts_get_by_label(list_head_t *l, const char *label)
{
	fswan_bpf_opts_t *opts;

	list_for_each_entry(opts, l, next) {
		if (!strncmp(opts->label, label, FSWAN_STR_MAX_LEN)) {
			return opts;
		}
	}

	return NULL;
}

void
fswan_bpf_opts_destroy(list_head_t *l)
{
	fswan_bpf_opts_t *opts, *_opts;

	list_for_each_entry_safe(opts, _opts, l, next)
		fswan_bpf_opts_del(opts);
	INIT_LIST_HEAD(l);
}

int
fswan_bpf_opts_load(fswan_bpf_opts_t *opts, vty_t *vty, int argc, const char **argv,
		    int (*bpf_load) (fswan_bpf_opts_t *))
{
	int err, ifindex;

	if (argc < 2) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return -1;
	}

	strlcpy(opts->label, argv[0], FSWAN_STR_MAX_LEN-1);
	strlcpy(opts->filename, argv[1], FSWAN_STR_MAX_LEN-1);
	ifindex = if_nametoindex(argv[2]);
	if (argc == 4)
		strlcpy(opts->progname, argv[3], FSWAN_STR_MAX_LEN-1);
	if (!ifindex) {
		vty_out(vty, "%% Error resolving interface %s (%m)%s"
			   , argv[2]
			   , VTY_NEWLINE);
		return -1;
	}
	opts->ifindex = ifindex;
	opts->vty = vty;

	err = (*bpf_load) (opts);
	if (err) {
		vty_out(vty, "%% Error loading eBPF program:%s on ifindex:%d%s"
			   , opts->filename
			   , opts->ifindex
			   , VTY_NEWLINE);
		/* Reset data */
		memset(opts, 0, sizeof(fswan_bpf_opts_t));
		return -1;
	}

	log_message(LOG_INFO, "Success loading eBPF program:%s on ifindex:%d"
			    , opts->filename
			    , opts->ifindex);
	return 0;
}


/*
 *	BPF related
 */
static int
fswan_bpf_log_message(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !(debug & 16))
		return 0;

	log_message(LOG_INFO, format, args);
	return 0;
}

struct bpf_map *
fswan_bpf_load_map(struct bpf_object *obj, const char *map_name)
{
	struct bpf_map *map = NULL;
	char errmsg[FSWAN_XDP_STRERR_BUFSIZE];

	map = bpf_object__find_map_by_name(obj, map_name);
	if (!map) {
		libbpf_strerror(errno, errmsg, FSWAN_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "%s(): BPF: error mapping tab:%s err:%d (%s)"
				    , __FUNCTION__
				    , map_name
				    , errno, errmsg);
		return NULL;
	}

	return map;
}

static void
fswan_bpf_cleanup_maps(struct bpf_object *obj, fswan_bpf_opts_t *opts)
{
	char errmsg[FSWAN_XDP_STRERR_BUFSIZE];
	struct bpf_map *map;
	vty_t *vty = opts->vty;

	bpf_object__for_each_map(map, obj) {
		char buf[FSWAN_STR_MAX_LEN];
		int len, err;

		len = snprintf(buf, FSWAN_STR_MAX_LEN, "%s/%d/%s"
						   , pin_basedir
						   , opts->ifindex
						   , bpf_map__name(map));
		if (len < 0) {
			vty_out(vty, "%% BPF: error preparing path for map(%s)%s"
				   , bpf_map__name(map), VTY_NEWLINE);
			return;
		}

		if (len > FSWAN_STR_MAX_LEN) {
			vty_out(vty, "%% BPF error, pathname too long to store map(%s)%s"
				   , bpf_map__name(map), VTY_NEWLINE);
			return;
		}

		if (access(buf, F_OK) != -1) {
			vty_out(vty, "BPF: unpinning previous map in %s%s"
				   , buf, VTY_NEWLINE);
			err = bpf_map__unpin(map, buf);
			if (err) {
				libbpf_strerror(err, errmsg, FSWAN_XDP_STRERR_BUFSIZE);
				vty_out(vty, "%% BPF error:%d (%s)%s"
					   , err, errmsg, VTY_NEWLINE);
				continue;
			}
		}
	}
}

static struct bpf_object *
fswan_bpf_load_file(fswan_bpf_opts_t *opts)
{
	struct bpf_object *bpf_obj;
	char errmsg[FSWAN_XDP_STRERR_BUFSIZE];
	vty_t *vty = opts->vty;
	int err;

	/* open eBPF file */
	bpf_obj = bpf_object__open(opts->filename);
	if (!bpf_obj) {
		libbpf_strerror(errno, errmsg, FSWAN_XDP_STRERR_BUFSIZE);
		vty_out(vty, "%% BPF: error opening bpf file err:%d (%s)%s"
			   , errno, errmsg, VTY_NEWLINE);
		return NULL;
	}

	/* Release previously stalled maps. Our lazzy strategy here is to
	 * simply erase previous maps during startup. Maybe if we want to
	 * implement some kind of graceful-restart we need to reuse-maps
	 * and rebuild local daemon tracking. Auto-pinning is done during
	 * bpf_object__load.
	 * FIXME: Implement graceful-restart */
	fswan_bpf_cleanup_maps(bpf_obj, opts);

	/* Finally load it */
	err = bpf_object__load(bpf_obj);
	if (err) {
		libbpf_strerror(err, errmsg, FSWAN_XDP_STRERR_BUFSIZE);
		vty_out(vty, "%% BPF: error loading bpf_object err:%d (%s)%s"
			   , err, errmsg, VTY_NEWLINE);
		bpf_object__close(bpf_obj);
		return NULL;
	}

	return bpf_obj;
}

static struct bpf_program *
fswan_bpf_load_prog(fswan_bpf_opts_t *opts)
{
	struct bpf_program *bpf_prog = NULL;
	struct bpf_object *bpf_obj;
	int len;

	/* Preprare pin_dir. We decided ifindex to be part of
	 * path to be able to load same bpf program on different
	 * ifindex */
	len = snprintf(opts->pin_root_path, FSWAN_STR_MAX_LEN, "%s/%d"
					  , pin_basedir, opts->ifindex);
	if (len < 0) {
		log_message(LOG_INFO, "%s(): Error preparing eBPF pin_dir for ifindex:%d"
				    , __FUNCTION__
				    , opts->ifindex);
		return NULL;
	}

	if (len > FSWAN_STR_MAX_LEN) {
		log_message(LOG_INFO, "%s(): Error preparing BPF pin_dir for ifindex:%d (path_too_long)"
				    , __FUNCTION__
				    , opts->ifindex);
		return NULL;
	}

	/* Load object */
	bpf_obj = fswan_bpf_load_file(opts);
	if (!bpf_obj)
		return NULL;

	/* Attach prog to interface */
	if (opts->progname[0]) {
		bpf_prog = bpf_object__find_program_by_name(bpf_obj, opts->progname);
		if (!bpf_prog) {
			log_message(LOG_INFO, "%s(): BPF: unknown program:%s (fallback to first one)"
					    , __FUNCTION__
					    , opts->progname);
		}
	}

	if (!bpf_prog) {
		bpf_prog = bpf_object__next_program(bpf_obj, NULL);
		if (!bpf_prog) {
			log_message(LOG_INFO, "%s(): BPF: no program found in file:%s"
					    , __FUNCTION__
					    , opts->filename);
			goto err;
		}
	}

	opts->bpf_obj = bpf_obj;
	return bpf_prog;

  err:
	bpf_object__close(bpf_obj);
	return NULL;
}


int
fswan_xdp_load(fswan_bpf_opts_t *opts)
{
	struct bpf_program *bpf_prog = NULL;
	struct bpf_link *bpf_lnk;
	char errmsg[FSWAN_XDP_STRERR_BUFSIZE];
	int err;

	/* Load eBPF prog */
	bpf_prog = fswan_bpf_load_prog(opts);
	if (!bpf_prog)
		return -1;

	/* Detach previously stalled XDP programm */
	err = bpf_xdp_detach(opts->ifindex, XDP_FLAGS_DRV_MODE, NULL);
	if (err) {
		libbpf_strerror(err, errmsg, FSWAN_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "%s(): Cant detach previous XDP programm (%s)"
				    , __FUNCTION__
				    , errmsg);
	}

	/* Attach XDP */
	bpf_lnk = bpf_program__attach_xdp(bpf_prog, opts->ifindex);
	if (!bpf_lnk) {
		libbpf_strerror(errno, errmsg, FSWAN_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "%s(): XDP: error attaching program:%s to ifindex:%d err:%d (%s)"
				    , __FUNCTION__
				    , bpf_program__name(bpf_prog)
				    , opts->ifindex
				    , errno, errmsg);
		goto err;
	}

	opts->bpf_lnk = bpf_lnk;
	return 0;

  err:
	return -1;
}

void
fswan_xdp_unload(fswan_bpf_opts_t *opts)
{
	bpf_link__destroy(opts->bpf_lnk);
	bpf_object__close(opts->bpf_obj);
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
	fswan_bpf_opts_destroy(&daemon_data->bpf_progs);
	return 0;
}
