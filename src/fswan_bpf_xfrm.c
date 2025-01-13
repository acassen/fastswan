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
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <linux/if_link.h>
#include <errno.h>
#include <libbpf.h>

/* local includes */
#include "fastswan.h"


/* Extern data */
extern data_t *daemon_data;

/*
 *	BPF MAP related
 */
static int
fswan_bpf_xfrm_map_load(fswan_bpf_opts_t *opts)
{
	int err = 0;

	/* MAP ref for faster access */
	opts->bpf_maps = MALLOC(sizeof(fswan_bpf_maps_t) * FSWAN_BPF_MAP_CNT);

	err = (err) ? : fswan_bpf_map_load(opts, "ipv4_xfrm_policy_lpm", FSWAN_BPF_MAP_IPV4_LPM);
	err = (err) ? : fswan_bpf_map_load(opts, "xfrm_offload_stats_hash", FSWAN_BPF_MAP_STATS_HASH);

	return err;
}

int
fswan_bpf_xfrm_load(fswan_bpf_opts_t *opts)
{
	vty_t *vty = opts->vty;
	int err;

	/* XDP Loading */
	err = fswan_xdp_load(opts);
	if (err)
		return -1;

	/* Loading MAPs */
	err = fswan_bpf_xfrm_map_load(opts);
	if (err) {
		vty_out(vty, "%% Error loading eBPF MAPs from program:%s on ifindex:%d%s"
			   , opts->filename
			   , opts->ifindex
			   , VTY_NEWLINE);

		/* Unload */
		if (opts->bpf_unload)
			(*opts->bpf_unload) (opts);

		/* Reset data */
		memset(opts, 0, sizeof(fswan_bpf_opts_t));
		return -1;
	}

	return 0;
}


/*
 *	XFRM Policy
 */
static int
fswan_bpf_xfrm_policy_set(xfrm_policy_t *p, struct ipv4_xfrm_policy *n)
{
	n->src_pfx_mask = inet_cidrtomask(p->prefixlen_s);
	n->src_pfx = p->saddr.a4;
	n->ifindex = p->ifindex;
	if (__test_bit(XFRM_POLICY_FL_IN_BIT, &p->flags))
		n->flags |= XFRM_POLICY_FL_INGRESS;
	if (__test_bit(XFRM_POLICY_FL_OUT_BIT, &p->flags))
		n->flags |= XFRM_POLICY_FL_EGRESS;
	return 0;
}

static int
fswan_bpf_xfrm_lpm_action(int action, fswan_bpf_opts_t *opts, xfrm_policy_t *p)
{
	struct bpf_map *map = opts->bpf_maps[FSWAN_BPF_MAP_IPV4_LPM].map;
	char errmsg[FSWAN_XDP_STRERR_BUFSIZE];
	struct ipv4_xfrm_policy *new = NULL;
	struct ipv4_lpm_key lpm_key = { .pfx_len = p->prefixlen_d, .pfx = p->daddr.a4 };
	int err = 0;

	/* We are getting XFRM netlink reflection msg */

	if (action == XFRM_MSG_NEWPOLICY) {
		PMALLOC(new);
		if (!new) {
			log_message(LOG_INFO, "%s(): Cant allocate ipv4_xfrm_policy !!!"
					    , __FUNCTION__);
			err = -1;
			goto end;
		}
		fswan_bpf_xfrm_policy_set(p, new);
		err = bpf_map__update_elem(map, &lpm_key, sizeof(struct ipv4_lpm_key)
					      , new, sizeof(struct ipv4_xfrm_policy)
					      , BPF_NOEXIST);
	} else if (action == XFRM_MSG_DELPOLICY) {
		err = bpf_map__delete_elem(map, &lpm_key, sizeof(struct ipv4_lpm_key), 0);
	} else
		return -1;

	if (err) {
		libbpf_strerror(err, errmsg, FSWAN_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "%s(): Cant %s xfrm policy for prefix:%u.%u.%u.%u/%d (%s)"
				    , __FUNCTION__
				    , (action == XFRM_MSG_NEWPOLICY) ? "add" : "del"
				    , NIPQUAD(p->daddr.a4), p->prefixlen_d
				    , errmsg);
		err = -1;
		goto end;
	}

	log_message(LOG_INFO, "%s(): %s: %s XFRM-Policy="
			      "{src:%u.%u.%u.%u/%d, dst:%u.%u.%u.%u/%d, ifindex:%d, dir:%s}"
			    , __FUNCTION__
			    , opts->label
			    , (action == XFRM_MSG_NEWPOLICY) ? "adding" : "deleting"
			    , NIPQUAD(p->saddr.a4), p->prefixlen_s
			    , NIPQUAD(p->daddr.a4), p->prefixlen_d
			    , p->ifindex
			    , __test_bit(XFRM_POLICY_FL_IN_BIT, &p->flags) ? "in" : "out");
  end:
	if (new)
		FREE(new);
	return err;
}

int
fswan_bpf_xfrm_action(int action, xfrm_policy_t *p)
{
	list_head_t *l = &daemon_data->bpf_progs;
	fswan_bpf_opts_t *opts;
	int err;

	/* If daemon is currently stopping, we simply skip action on ruleset.
	 * This reduce daemon exit time and entries are properly released during
	 * kernel BPF map release. */
	if (__test_bit(FSWAN_FL_STOP_BIT, &daemon_data->flags))
		return 0;

	if (!__test_bit(FSWAN_FL_XDP_XFRM_LOADED_BIT, &daemon_data->flags))
		return -1;

	/* FIXME: Add support to IPv6 */
	if (p->family != AF_INET)
		return -1;

	/* perform action on every loaded bpf prog */
	list_for_each_entry(opts, l, next) {
		err = fswan_bpf_xfrm_lpm_action(action, opts, p);
		if (err) {
			return -1;
		}
	}

	return 0;
}

int
fswan_xfrm_policy_vty(vty_t *vty)
{
	struct ipv4_lpm_key key = {.pfx_len = 0, .pfx = 0}, next_key = {.pfx_len = 0, .pfx = 0};
	fswan_bpf_opts_t *opts;
	struct bpf_map *map;
	struct ipv4_xfrm_policy *p;
	char errmsg[FSWAN_XDP_STRERR_BUFSIZE];
	char ifname[IF_NAMESIZE];
	int err = 0;

	/* rules are mirred into every eBPF progs, first one is good enough */
	opts = list_first_entry(&daemon_data->bpf_progs, fswan_bpf_opts_t, next);
	map = opts->bpf_maps[FSWAN_BPF_MAP_IPV4_LPM].map;

	PMALLOC(p);

	while (bpf_map__get_next_key(map, &key, &next_key, sizeof(struct ipv4_lpm_key)) == 0) {
		key = next_key;
		err = bpf_map__lookup_elem(map, &key, sizeof(struct ipv4_lpm_key)
					      , p, sizeof(*p), 0);
		if (err) {
			libbpf_strerror(err, errmsg, FSWAN_XDP_STRERR_BUFSIZE);
			vty_out(vty, "%% error fetching value for pfx:%u.%u.%u.%u/%u (%s)%s"
				   , NIPQUAD(key.pfx), key.pfx_len, errmsg, VTY_NEWLINE);
			continue;
		}

		vty_out(vty, " src %u.%u.%u.%u/%u dst %u.%u.%u.%u/%u dir %s dev %s%s"
			   , NIPQUAD(p->src_pfx), inet_masktocidr(p->src_pfx_mask)
			   , NIPQUAD(key.pfx), key.pfx_len
			   , (p->flags & XFRM_POLICY_FL_INGRESS) ? "in" : "out"
			   , if_indextoname(p->ifindex, ifname)
			   , VTY_NEWLINE);
	}

	FREE(p);
	return 0;
}


/*
 *	XFRM Statistics
 */
static void
fswan_if_stats_reset(void)
{
	list_head_t *l = &daemon_data->interfaces;
	interface_t *ifi;

	list_for_each_entry(ifi, l, next) {
		ifi->rx_pkts = 0;
		ifi->rx_bytes = 0;
		ifi->tx_pkts = 0;
		ifi->tx_bytes = 0;
	}
}

static interface_t *
fswan_if_get_by_ifindex(int ifindex)
{
	list_head_t *l = &daemon_data->interfaces;
	interface_t *ifi;

	list_for_each_entry(ifi, l, next) {
		if (ifi->ifindex == ifindex)
			return ifi;
	}

	return NULL;
}

static struct xfrm_offload_stats *
fswan_bpf_xfrm_stats_alloc(size_t *sz)
{
	unsigned int nr_cpus = libbpf_num_possible_cpus();
	struct xfrm_offload_stats *new;

	new = calloc(nr_cpus, sizeof(*new));
	if (!new)
		return NULL;

	*sz = nr_cpus * sizeof(struct xfrm_offload_stats);

	return new;
}

static void
fswan_bpf_xfrm_stats_set(struct xfrm_offload_stats *s, int ifindex)
{
	unsigned int nr_cpus = libbpf_num_possible_cpus();
	int i;

	for (i = 0; i < nr_cpus; i++) {
		memset(&s[i], 0, sizeof(*s));
		s[i].ifindex = ifindex;
	}
}

static int
fswan_xfrm_offload_stats_update(vty_t *vty, fswan_bpf_opts_t *opts)
{
	struct bpf_map *map = opts->bpf_maps[FSWAN_BPF_MAP_STATS_HASH].map;
	unsigned int nr_cpus = libbpf_num_possible_cpus();
	struct xfrm_offload_stats *s;
	uint32_t key = 0, next_key = 0;
	char errmsg[FSWAN_XDP_STRERR_BUFSIZE];
	uint64_t rx_pkts, rx_bytes, tx_pkts, tx_bytes;
	interface_t *ifi;
	int err = 0;
	size_t sz;
	int i;

	s = fswan_bpf_xfrm_stats_alloc(&sz);
	if (!s) {
		vty_out(vty, "%% Cant allocate temp xfrm_offload_stats%s", VTY_NEWLINE);
		return -1;
	}

	/* Walk hashtab */
	while (bpf_map__get_next_key(map, &key, &next_key, sizeof(uint32_t)) == 0) {
		key = next_key;
		err = bpf_map__lookup_elem(map, &key, sizeof(uint32_t), s, sz, 0);
		if (err) {
			libbpf_strerror(err, errmsg, FSWAN_XDP_STRERR_BUFSIZE);
			vty_out(vty, "%% error fetching value for ifindex:%d (%s)%s"
				   , key, errmsg, VTY_NEWLINE);
			continue;
		}

		rx_pkts = rx_bytes = tx_pkts = tx_bytes = 0;
		for (i = 0; i < nr_cpus; i++) {
			rx_pkts += s[i].rx_pkts;
			rx_bytes += s[i].rx_bytes;
			tx_pkts += s[i].tx_pkts;
			tx_bytes += s[i].tx_bytes;
		}

		if (!rx_pkts && !tx_pkts)
			continue;

		ifi = fswan_if_get_by_ifindex(s->ifindex);
		if (ifi) {
			ifi->rx_pkts += rx_pkts;
			ifi->rx_bytes += rx_bytes;
			ifi->tx_pkts += tx_pkts;
			ifi->tx_bytes += tx_bytes;
		}
	}

	free(s);
	return 0;
}

static int
fswan_xfrm_offload_stats_vty(vty_t *vty)
{
	list_head_t *l = &daemon_data->interfaces;
	interface_t *ifi;

	list_for_each_entry(ifi, l, next) {
		if (!ifi->rx_pkts && !ifi->tx_pkts)
			continue;

		vty_out(vty, " %s:%s"
			     "   rx_pkts:%ld rx_bytes:%ld%s"
			     "   tx_pkts:%ld tx_bytes:%ld%s"
			   , ifi->ifname, VTY_NEWLINE
			   , ifi->rx_pkts, ifi->rx_bytes, VTY_NEWLINE
			   , ifi->tx_pkts, ifi->tx_bytes, VTY_NEWLINE);
	}

	return 0;
}

int
fswan_xfrm_stats_vty(vty_t *vty)
{
	list_head_t *l = &daemon_data->bpf_progs;
	fswan_bpf_opts_t *opts;

	fswan_if_stats_reset();
	list_for_each_entry(opts, l, next)
		fswan_xfrm_offload_stats_update(vty, opts);
	fswan_xfrm_offload_stats_vty(vty);
	return 0;
}

static int
fswan_bpf_xfrm_stats_insert(fswan_bpf_opts_t *opts, struct xfrm_offload_stats *s, size_t sz)
{
	struct bpf_map *map = opts->bpf_maps[FSWAN_BPF_MAP_STATS_HASH].map;
	uint32_t key = s[0].ifindex;
	char errmsg[FSWAN_XDP_STRERR_BUFSIZE];
	int err = 0;

	err = bpf_map__update_elem(map, &key, sizeof(uint32_t), s, sz, BPF_NOEXIST);
	if (err) {
		libbpf_strerror(err, errmsg, FSWAN_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "%s(): Cant init xfrm_stats for ifindex:%d (%s)"
				    , __FUNCTION__
				    , key
				    , errmsg);
		return -1;
	}

	return 0;
}

int
fswan_bpf_xfrm_stats_init(fswan_bpf_opts_t *opts)
{
	list_head_t *l = &daemon_data->interfaces;
	struct xfrm_offload_stats *new;
	interface_t *ifi;
	size_t sz;
	int err;

	list_for_each_entry(ifi, l, next) {
		new = fswan_bpf_xfrm_stats_alloc(&sz);
		if (!new)
			return -1;

		fswan_bpf_xfrm_stats_set(new, ifi->ifindex);
		err = fswan_bpf_xfrm_stats_insert(opts, new, sz);
		free(new);
		if (err)
			return -1;
	}

	return 0;
}
