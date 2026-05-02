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
#include <libbpf.h>

/* local includes */
#include "memory.h"
#include "logger.h"
#include "bitops.h"
#include "vty.h"
#include "inet_utils.h"
#include "fswan_data.h"
#include "fswan_if.h"
#include "fswan_bpf.h"
#include "fswan_bpf_xfrm.h"
#include "fswan_netlink.h"


/* Extern data */
extern struct data *daemon_data;

/*
 *	BPF MAP related
 *
 *	Called from fswan_bpf_prog_load() right after bpf_object__load(),
 *	wires the xfrm-specific maps into the program's bpf_maps array.
 */
int
fswan_bpf_xfrm_map_load(struct fswan_bpf_prog *p)
{
	int err;

	p->bpf_maps = MALLOC(sizeof(struct fswan_bpf_maps) * FSWAN_BPF_MAP_CNT);
	if (!p->bpf_maps)
		return -1;

	err = fswan_bpf_map_load(p, "dst_lpm", FSWAN_BPF_MAP_DST_LPM);
	err = err ? : fswan_bpf_map_load(p, "policy_lpm", FSWAN_BPF_MAP_POLICY_LPM);
	err = err ? : fswan_bpf_map_load(p, "xfrm_policy_stats_array", FSWAN_BPF_MAP_POLICY_STATS_ARRAY);
	err = err ? : fswan_bpf_map_load(p, "xfrm_offload_stats_hash", FSWAN_BPF_MAP_STATS_HASH);
	err = err ? : fswan_bpf_map_load(p, "hairpin_map", FSWAN_BPF_MAP_HAIRPIN);

	return err;
}


/*
 *	Bitmap allocator (shared by dst_id and stats_slot allocators)
 */
static int
fswan_bpf_bitmap_alloc(unsigned long *bitmap, int max)
{
	int i;

	for (i = 0; i < max; i++) {
		if (!__test_and_set_bit_array(i, bitmap))
			return i;
	}
	return -1;
}

static void
fswan_bpf_bitmap_free(unsigned long *bitmap, int idx, int max)
{
	if (idx < 0 || idx >= max)
		return;
	__clear_bit_array(idx, bitmap);
}


/*
 *	dst_id allocator
 *
 *	Each unique (daddr, prefixlen_d) maps to a 32-bit token stored in
 *	dst_lpm. Tokens are reference-counted so multiple policy_lpm entries
 *	(same dst, different src) share one dst_lpm entry.
 */
static int
fswan_bpf_xfrm_dst_id_get(struct fswan_bpf_prog *opts, __be32 daddr,
			  uint32_t prefixlen_d, uint32_t *dst_id_out)
{
	struct bpf_map *map = opts->bpf_maps[FSWAN_BPF_MAP_DST_LPM].map;
	struct ipv4_dst_lpm_key key = { .prefixlen = prefixlen_d, .dst = daddr };
	uint32_t dst_id;
	int err, id;

	err = bpf_map__lookup_elem(map, &key, sizeof(key), &dst_id, sizeof(dst_id), 0);
	if (!err && dst_id < FSWAN_BPF_DST_ID_MAX) {
		opts->dst_id_refcount[dst_id]++;
		*dst_id_out = dst_id;
		return 0;
	}

	id = fswan_bpf_bitmap_alloc(opts->dst_id_bitmap, FSWAN_BPF_DST_ID_MAX);
	if (id < 0)
		return -1;

	dst_id = id;
	err = bpf_map__update_elem(map, &key, sizeof(key), &dst_id, sizeof(dst_id),
				   BPF_NOEXIST);
	if (err) {
		fswan_bpf_bitmap_free(opts->dst_id_bitmap, id, FSWAN_BPF_DST_ID_MAX);
		return err;
	}

	opts->dst_id_refcount[id] = 1;
	*dst_id_out = dst_id;
	return 0;
}

static void
fswan_bpf_xfrm_dst_id_put(struct fswan_bpf_prog *opts, __be32 daddr,
			  uint32_t prefixlen_d, uint32_t dst_id)
{
	struct bpf_map *map = opts->bpf_maps[FSWAN_BPF_MAP_DST_LPM].map;
	struct ipv4_dst_lpm_key key = { .prefixlen = prefixlen_d, .dst = daddr };

	if (dst_id >= FSWAN_BPF_DST_ID_MAX)
		return;
	if (--opts->dst_id_refcount[dst_id] > 0)
		return;

	bpf_map__delete_elem(map, &key, sizeof(key), 0);
	fswan_bpf_bitmap_free(opts->dst_id_bitmap, dst_id, FSWAN_BPF_DST_ID_MAX);
}


/*
 *	Per-policy stats slot
 */
static int
fswan_bpf_xfrm_stats_slot_zero(struct fswan_bpf_prog *opts, uint32_t slot)
{
	struct bpf_map *map = opts->bpf_maps[FSWAN_BPF_MAP_POLICY_STATS_ARRAY].map;
	unsigned int nr_cpus = libbpf_num_possible_cpus();
	struct xfrm_policy_stats *zeros;
	size_t sz = nr_cpus * sizeof(*zeros);
	int err;

	zeros = calloc(nr_cpus, sizeof(*zeros));
	if (!zeros)
		return -1;

	err = bpf_map__update_elem(map, &slot, sizeof(slot), zeros, sz, 0);
	free(zeros);
	return err;
}


/*
 *	XFRM Policy add/del
 */
static void
fswan_bpf_xfrm_policy_value_set(struct xfrm_policy *p, struct ipv4_xfrm_policy *v,
				uint32_t slot)
{
	v->ifindex = p->ifindex;
	v->stats_slot = slot;
	v->flags = 0;
	if (__test_bit(XFRM_POLICY_FL_IN_BIT, &p->flags))
		v->flags |= XFRM_POLICY_FL_INGRESS;
	if (__test_bit(XFRM_POLICY_FL_OUT_BIT, &p->flags))
		v->flags |= XFRM_POLICY_FL_EGRESS;
	if (__test_bit(FSWAN_FL_XDP_XFRM_DISABLE_STATS_BIT, &daemon_data->flags))
		v->flags |= XFRM_POLICY_FL_NO_STATS;
}

static void
fswan_bpf_xfrm_policy_key_set(struct xfrm_policy *p, uint32_t dst_id,
			      struct ipv4_policy_lpm_key *key)
{
	key->prefixlen = 32 + p->prefixlen_s;
	key->dst_id = dst_id;
	key->src = p->saddr.a4;
}

static int
fswan_bpf_xfrm_lpm_add(struct fswan_bpf_prog *opts, struct xfrm_policy *p)
{
	struct bpf_map *policy_map = opts->bpf_maps[FSWAN_BPF_MAP_POLICY_LPM].map;
	struct ipv4_xfrm_policy val;
	struct ipv4_policy_lpm_key key;
	uint32_t dst_id;
	int slot, err;

	err = fswan_bpf_xfrm_dst_id_get(opts, p->daddr.a4, p->prefixlen_d, &dst_id);
	if (err)
		return err;

	slot = fswan_bpf_bitmap_alloc(opts->stats_slot_bitmap, XFRM_POLICY_MAX);
	if (slot < 0) {
		fswan_bpf_xfrm_dst_id_put(opts, p->daddr.a4, p->prefixlen_d, dst_id);
		log_message(LOG_INFO, "%s(): Out of stats slots for xfrm policy"
					" %u.%u.%u.%u/%d"
				    , __FUNCTION__
				    , NIPQUAD(p->daddr.a4), p->prefixlen_d);
		return -1;
	}

	fswan_bpf_xfrm_stats_slot_zero(opts, slot);
	fswan_bpf_xfrm_policy_value_set(p, &val, slot);
	fswan_bpf_xfrm_policy_key_set(p, dst_id, &key);

	err = bpf_map__update_elem(policy_map, &key, sizeof(key), &val, sizeof(val),
				   BPF_NOEXIST);
	if (err) {
		fswan_bpf_bitmap_free(opts->stats_slot_bitmap, slot, XFRM_POLICY_MAX);
		fswan_bpf_xfrm_dst_id_put(opts, p->daddr.a4, p->prefixlen_d, dst_id);
		return err;
	}

	return 0;
}

static int
fswan_bpf_xfrm_lpm_del(struct fswan_bpf_prog *opts, struct xfrm_policy *p)
{
	struct bpf_map *dst_map = opts->bpf_maps[FSWAN_BPF_MAP_DST_LPM].map;
	struct bpf_map *policy_map = opts->bpf_maps[FSWAN_BPF_MAP_POLICY_LPM].map;
	struct ipv4_dst_lpm_key dk = { .prefixlen = p->prefixlen_d,
				       .dst = p->daddr.a4 };
	struct ipv4_policy_lpm_key pk;
	struct ipv4_xfrm_policy val;
	uint32_t dst_id;
	int err;

	err = bpf_map__lookup_elem(dst_map, &dk, sizeof(dk), &dst_id, sizeof(dst_id), 0);
	if (err)
		return err;

	fswan_bpf_xfrm_policy_key_set(p, dst_id, &pk);

	err = bpf_map__lookup_elem(policy_map, &pk, sizeof(pk), &val, sizeof(val), 0);
	if (err)
		return err;

	err = bpf_map__delete_elem(policy_map, &pk, sizeof(pk), 0);
	if (err)
		return err;

	fswan_bpf_bitmap_free(opts->stats_slot_bitmap, val.stats_slot, XFRM_POLICY_MAX);
	fswan_bpf_xfrm_dst_id_put(opts, p->daddr.a4, p->prefixlen_d, dst_id);
	return 0;
}


static int
fswan_bpf_xfrm_lpm_action(int action, struct fswan_bpf_prog *opts, struct xfrm_policy *p)
{
	char errmsg[FSWAN_XDP_STRERR_BUFSIZE];
	int err = 0;

	/* We are getting XFRM netlink reflection msg */
	if (action == XFRM_MSG_NEWPOLICY) {
		err = fswan_bpf_xfrm_lpm_add(opts, p);
	} else if (action == XFRM_MSG_DELPOLICY) {
		err = fswan_bpf_xfrm_lpm_del(opts, p);
	} else
		return -1;

	if (err) {
		libbpf_strerror(err, errmsg, FSWAN_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "%s(): Cant %s xfrm policy for prefix:%u.%u.%u.%u/%d (%s)"
				    , __FUNCTION__
				    , (action == XFRM_MSG_NEWPOLICY) ? "add" : "del"
				    , NIPQUAD(p->daddr.a4), p->prefixlen_d
				    , errmsg);
		return -1;
	}

	log_message(LOG_INFO, "%s(): %s: %s XFRM-Policy="
			      "{src:%u.%u.%u.%u/%d, dst:%u.%u.%u.%u/%d, ifindex:%d, dir:%s}"
			    , __FUNCTION__
			    , opts->name
			    , (action == XFRM_MSG_NEWPOLICY) ? "adding" : "deleting"
			    , NIPQUAD(p->saddr.a4), p->prefixlen_s
			    , NIPQUAD(p->daddr.a4), p->prefixlen_d
			    , p->ifindex
			    , __test_bit(XFRM_POLICY_FL_IN_BIT, &p->flags) ? "in" : "out");
	return 0;
}

int
fswan_bpf_xfrm_action(int action, struct xfrm_policy *p)
{
	struct interface *iface;

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

	iface = fswan_if_get_by_ifindex(p->ifindex, false);
	if (!iface || !iface->bpf_prog)
		return 0;

	return fswan_bpf_xfrm_lpm_action(action, iface->bpf_prog, p);
}


/*
 *	XFRM Policy display
 */
static void
fswan_bpf_xfrm_policy_counters_vty(struct vty *vty, struct fswan_bpf_prog *opts,
				   struct ipv4_xfrm_policy *val)
{
	struct bpf_map *map = opts->bpf_maps[FSWAN_BPF_MAP_POLICY_STATS_ARRAY].map;
	unsigned int nr_cpus = libbpf_num_possible_cpus();
	uint64_t pkts = 0, bytes = 0;
	struct xfrm_policy_stats *s;
	uint32_t slot = val->stats_slot;
	size_t sz = nr_cpus * sizeof(*s);
	int i, err;

	if (slot >= XFRM_POLICY_MAX)
		return;

	s = calloc(nr_cpus, sizeof(*s));
	if (!s) {
		vty_out(vty, "%% Cant allocate temp xfrm_policy_stats%s", VTY_NEWLINE);
		return;
	}

	err = bpf_map__lookup_elem(map, &slot, sizeof(slot), s, sz, 0);
	if (err) {
		vty_out(vty, "%% Cant get xfrm_policy_stats%s", VTY_NEWLINE);
		goto end;
	}

	for (i = 0; i < (int) nr_cpus; i++) {
		pkts += s[i].pkts;
		bytes += s[i].bytes;
	}

	vty_out(vty, "   %s:\tpkts:%ld bytes:%ld%s"
		   , opts->name, pkts, bytes, VTY_NEWLINE);
end:
	free(s);
}

static int
fswan_bpf_xfrm_policy_lookup_in_prog(struct fswan_bpf_prog *opts,
				     struct ipv4_dst_lpm_key *dk,
				     struct ipv4_policy_lpm_key *pk_in,
				     struct ipv4_xfrm_policy *val_out)
{
	struct bpf_map *dst_map = opts->bpf_maps[FSWAN_BPF_MAP_DST_LPM].map;
	struct bpf_map *policy_map = opts->bpf_maps[FSWAN_BPF_MAP_POLICY_LPM].map;
	struct ipv4_policy_lpm_key pk;
	uint32_t dst_id;
	int err;

	err = bpf_map__lookup_elem(dst_map, dk, sizeof(*dk), &dst_id, sizeof(dst_id), 0);
	if (err)
		return err;

	pk.prefixlen = pk_in->prefixlen;
	pk.dst_id = dst_id;
	pk.src = pk_in->src;

	return bpf_map__lookup_elem(policy_map, &pk, sizeof(pk),
				    val_out, sizeof(*val_out), 0);
}

static void
fswan_bpf_xfrm_policy_stats_vty(struct vty *vty, struct fswan_bpf_prog *o,
				struct ipv4_dst_lpm_key *dk,
				struct ipv4_policy_lpm_key *pk,
				struct ipv4_xfrm_policy *val_o)
{
	struct list_head *l = &daemon_data->bpf_progs;
	struct fswan_bpf_prog *opts;
	struct ipv4_xfrm_policy val;

	if (__test_bit(FSWAN_FL_XDP_XFRM_DISABLE_STATS_BIT, &daemon_data->flags))
		return;

	list_for_each_entry(opts, l, next) {
		if (opts == o) {
			fswan_bpf_xfrm_policy_counters_vty(vty, opts, val_o);
			continue;
		}

		if (fswan_bpf_xfrm_policy_lookup_in_prog(opts, dk, pk, &val))
			continue;

		fswan_bpf_xfrm_policy_counters_vty(vty, opts, &val);
	}
}

static void
fswan_bpf_xfrm_policy_pfx_vty(struct vty *vty, struct fswan_bpf_prog *opts,
			      struct ipv4_dst_lpm_key *dk,
			      struct ipv4_policy_lpm_key *pk,
			      struct ipv4_xfrm_policy *val, bool stats)
{
	uint32_t src_bits = pk->prefixlen >= 32 ? pk->prefixlen - 32 : 0;
	char ifname[IF_NAMESIZE];

	if (!src_bits) {
		vty_out(vty, " dst %u.%u.%u.%u/%u dir %s dev %s%s"
			   , NIPQUAD(dk->dst), dk->prefixlen
			   , (val->flags & XFRM_POLICY_FL_INGRESS) ? "in" : "out"
			   , if_indextoname(val->ifindex, ifname), VTY_NEWLINE);
	} else {
		vty_out(vty, " src %u.%u.%u.%u/%u dst %u.%u.%u.%u/%u dir %s dev %s%s"
			   , NIPQUAD(pk->src), src_bits
			   , NIPQUAD(dk->dst), dk->prefixlen
			   , (val->flags & XFRM_POLICY_FL_INGRESS) ? "in" : "out"
			   , if_indextoname(val->ifindex, ifname), VTY_NEWLINE);
	}

	if (stats)
		fswan_bpf_xfrm_policy_stats_vty(vty, opts, dk, pk, val);
}

/*
 *	Build a dst_id -> dst_lpm_key reverse table for one program. The
 *	table is used by the policy walker to resolve dst_id back to its
 *	(prefixlen, dst) pair without walking dst_lpm per policy entry.
 */
static int
fswan_bpf_xfrm_dst_table_build(struct fswan_bpf_prog *opts,
			       struct ipv4_dst_lpm_key *table)
{
	struct bpf_map *map = opts->bpf_maps[FSWAN_BPF_MAP_DST_LPM].map;
	struct ipv4_dst_lpm_key key = { 0 }, next_key;
	uint32_t dst_id;

	while (bpf_map__get_next_key(map, &key, &next_key, sizeof(key)) == 0) {
		key = next_key;
		if (bpf_map__lookup_elem(map, &key, sizeof(key),
					 &dst_id, sizeof(dst_id), 0))
			continue;
		if (dst_id < FSWAN_BPF_DST_ID_MAX)
			table[dst_id] = key;
	}
	return 0;
}

static int
fswan_bpf_xfrm_policy_vty(struct vty *vty, bool stats)
{
	struct ipv4_policy_lpm_key key = { 0 }, next_key;
	struct ipv4_dst_lpm_key *dst_table;
	struct ipv4_xfrm_policy val;
	struct fswan_bpf_prog *opts;
	struct bpf_map *map;

	/* rules are mirred into every eBPF progs, first one is good enough */
	opts = list_first_entry(&daemon_data->bpf_progs, struct fswan_bpf_prog, next);
	map = opts->bpf_maps[FSWAN_BPF_MAP_POLICY_LPM].map;

	dst_table = calloc(FSWAN_BPF_DST_ID_MAX, sizeof(*dst_table));
	if (!dst_table) {
		vty_out(vty, "%% Cant allocate dst_id table%s", VTY_NEWLINE);
		return -1;
	}
	fswan_bpf_xfrm_dst_table_build(opts, dst_table);

	while (bpf_map__get_next_key(map, &key, &next_key, sizeof(key)) == 0) {
		key = next_key;
		if (bpf_map__lookup_elem(map, &key, sizeof(key),
					 &val, sizeof(val), 0))
			continue;
		if (key.dst_id >= FSWAN_BPF_DST_ID_MAX)
			continue;

		fswan_bpf_xfrm_policy_pfx_vty(vty, opts, &dst_table[key.dst_id],
					      &key, &val, stats);
	}

	free(dst_table);
	return 0;
}

int
fswan_xfrm_policy_vty(struct vty *vty)
{
	return fswan_bpf_xfrm_policy_vty(vty, false);
}

int
fswan_xfrm_policy_stats_vty(struct vty *vty)
{
	return fswan_bpf_xfrm_policy_vty(vty, true);
}


/*
 *	XFRM Statistics
 */
static void
fswan_if_stats_reset(void)
{
	struct list_head *l = &daemon_data->interfaces;
	struct interface *ifi;

	list_for_each_entry(ifi, l, next) {
		ifi->rx_pkts = 0;
		ifi->rx_bytes = 0;
		ifi->tx_pkts = 0;
		ifi->tx_bytes = 0;
	}
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
fswan_xfrm_offload_stats_update(struct vty *vty, struct fswan_bpf_prog *opts)
{
	struct bpf_map *map = opts->bpf_maps[FSWAN_BPF_MAP_STATS_HASH].map;
	unsigned int nr_cpus = libbpf_num_possible_cpus();
	struct xfrm_offload_stats *s;
	uint32_t key = 0, next_key = 0;
	char errmsg[FSWAN_XDP_STRERR_BUFSIZE];
	uint64_t rx_pkts, rx_bytes, tx_pkts, tx_bytes;
	struct interface *ifi;
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

		ifi = fswan_if_get_by_ifindex(s->ifindex, false);
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
fswan_xfrm_offload_stats_vty(struct vty *vty)
{
	struct list_head *l = &daemon_data->interfaces;
	struct interface *ifi;

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
fswan_xfrm_stats_vty(struct vty *vty)
{
	struct list_head *l = &daemon_data->bpf_progs;
	struct fswan_bpf_prog *opts;

	if (__test_bit(FSWAN_FL_XDP_XFRM_DISABLE_STATS_BIT, &daemon_data->flags)) {
		vty_out(vty, "%% Statistics are currently disabled...%s", VTY_NEWLINE);
		return 0;
	}

	fswan_if_stats_reset();
	list_for_each_entry(opts, l, next)
		fswan_xfrm_offload_stats_update(vty, opts);
	fswan_xfrm_offload_stats_vty(vty);
	return 0;
}

static int
fswan_bpf_xfrm_stats_insert(struct fswan_bpf_prog *opts, struct xfrm_offload_stats *s, size_t sz)
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
fswan_bpf_xfrm_stats_iface_register(struct fswan_bpf_prog *p, struct interface *iface)
{
	struct xfrm_offload_stats *new;
	size_t sz;
	int err;

	new = fswan_bpf_xfrm_stats_alloc(&sz);
	if (!new)
		return -1;

	fswan_bpf_xfrm_stats_set(new, iface->ifindex);
	err = fswan_bpf_xfrm_stats_insert(p, new, sz);
	free(new);
	return err;
}

int
fswan_bpf_xfrm_stats_iface_unregister(struct fswan_bpf_prog *p, struct interface *iface)
{
	struct bpf_map *map = p->bpf_maps[FSWAN_BPF_MAP_STATS_HASH].map;
	uint32_t key = iface->ifindex;
	char errmsg[FSWAN_XDP_STRERR_BUFSIZE];
	int err;

	err = bpf_map__delete_elem(map, &key, sizeof(uint32_t), 0);
	if (err) {
		libbpf_strerror(err, errmsg, FSWAN_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "%s(): Cant del xfrm_stats for ifindex:%d (%s)"
				    , __FUNCTION__
				    , key
				    , errmsg);
		return -1;
	}

	return 0;
}
