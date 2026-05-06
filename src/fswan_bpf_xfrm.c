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
#include "table.h"
#include "inet_utils.h"
#include "fswan_data.h"
#include "fswan_if.h"
#include "fswan_bpf.h"
#include "fswan_bpf_xfrm.h"
#include "fswan_netlink.h"
#include "fswan_flower.h"


/* Extern data */
extern struct data *daemon_data;

/*
 *	BPF MAP related
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
	err = err ? : fswan_bpf_map_load(p, "hairpin_map", FSWAN_BPF_MAP_HAIRPIN);
	err = err ? : fswan_bpf_map_load(p, "iface_topo", FSWAN_BPF_MAP_IFACE_TOPO);

	return err;
}


/*
 * 	System interface topology mirroring
 */
static int
fswan_bpf_iface_topo_write(struct fswan_bpf_prog *p, struct interface *iface)
{
	struct iface_topo val = {};
	struct bpf_map *map;
	uint32_t key = iface->ifindex;

	if (!p || !p->bpf_maps)
		return 0;
	if (__test_bit(FSWAN_BPF_PROG_FL_SHUTDOWN_BIT, &p->flags))
		return 0;
	map = p->bpf_maps[FSWAN_BPF_MAP_IFACE_TOPO].map;
	if (!map)
		return 0;
	if (key >= IFACE_TOPO_MAP_MAX_ENTRIES) {
		log_message(LOG_INFO, "%s(): ifindex %u out of iface_topo map range"
				    , __FUNCTION__, key);
		return -1;
	}

	if (iface->vlan_id && iface->link_iface) {
		val.vlan_id      = iface->vlan_id;
		val.link_ifindex = iface->link_iface->ifindex;
	}
	return bpf_map__update_elem(map, &key, sizeof(key),
				    &val, sizeof(val), 0);
}

void
fswan_bpf_iface_topo_publish(struct interface *iface)
{
	struct fswan_bpf_prog *p;

	list_for_each_entry(p, &daemon_data->bpf_progs, next)
		fswan_bpf_iface_topo_write(p, iface);
}

void
fswan_bpf_iface_topo_seed(struct fswan_bpf_prog *p)
{
	struct interface *iface;

	list_for_each_entry(iface, &daemon_data->interfaces, next)
		fswan_bpf_iface_topo_write(p, iface);
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
 *
 *	Slot 0 is the BPF-side "stats disabled" sentinel (reserved at
 *	prog alloc).
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

static int
fswan_bpf_xfrm_stats_slot_alloc(struct fswan_bpf_prog *opts)
{
	int slot;

	if (__test_bit(FSWAN_FL_XDP_XFRM_DISABLE_STATS_BIT, &daemon_data->flags))
		return 0;

	slot = fswan_bpf_bitmap_alloc(opts->stats_slot_bitmap, XFRM_POLICY_MAX);
	if (slot < 0)
		return -1;

	fswan_bpf_xfrm_stats_slot_zero(opts, slot);
	return slot;
}

static void
fswan_bpf_xfrm_stats_slot_free(struct fswan_bpf_prog *opts, uint32_t slot)
{
	if (!slot)
		return;
	fswan_bpf_bitmap_free(opts->stats_slot_bitmap, slot, XFRM_POLICY_MAX);
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

	slot = fswan_bpf_xfrm_stats_slot_alloc(opts);
	if (slot < 0) {
		log_message(LOG_INFO, "%s(): Out of stats slots for xfrm policy"
					" %u.%u.%u.%u/%d"
				    , __FUNCTION__
				    , NIPQUAD(p->daddr.a4), p->prefixlen_d);
		err = -1;
		goto err_dst_id;
	}

	fswan_bpf_xfrm_policy_value_set(p, &val, slot);
	fswan_bpf_xfrm_policy_key_set(p, dst_id, &key);

	err = bpf_map__update_elem(policy_map, &key, sizeof(key), &val, sizeof(val),
				   BPF_NOEXIST);
	if (err)
		goto err_slot;

	return 0;

 err_slot:
	fswan_bpf_xfrm_stats_slot_free(opts, slot);
 err_dst_id:
	fswan_bpf_xfrm_dst_id_put(opts, p->daddr.a4, p->prefixlen_d, dst_id);
	return err;
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

	fswan_bpf_xfrm_stats_slot_free(opts, val.stats_slot);
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

	/* FIXME: Add support to IPv6 */
	if (p->family != AF_INET)
		return -1;

	iface = fswan_if_get_by_ifindex(p->ifindex, false);
	if (!iface)
		return 0;

	/* flower-mode owns outbound on this iface; inbound stays on XDP. */
	if (iface->flower &&
	    __test_bit(XFRM_POLICY_FL_OUT_BIT, &p->flags))
		return fswan_flower_xfrm_action(action, iface, p);

	if (!iface->bpf_prog || !iface->bpf_prog->bpf_maps)
		return 0;
	if (__test_bit(FSWAN_BPF_PROG_FL_SHUTDOWN_BIT, &iface->bpf_prog->flags))
		return 0;
	return fswan_bpf_xfrm_lpm_action(action, iface->bpf_prog, p);
}


/*
 *	XFRM Policy display
 */
void
fswan_bpf_xfrm_policy_counters_vty(struct vty *vty, struct fswan_bpf_prog *opts,
				   struct ipv4_xfrm_policy *val)
{
	struct bpf_map *map = opts->bpf_maps[FSWAN_BPF_MAP_POLICY_STATS_ARRAY].map;
	unsigned int nr_cpus = libbpf_num_possible_cpus();
	struct xfrm_policy_stats *s;
	uint32_t slot = val->stats_slot;
	size_t sz = nr_cpus * sizeof(*s);
	int i, err;

	if (!slot || slot >= XFRM_POLICY_MAX)
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

	for (i = 1; i < nr_cpus; i++) {
		s[0].pkts += s[i].pkts;
		s[0].bytes += s[i].bytes;
	}

	vty_out(vty, "            %s: pkts:%llu bytes:%llu%s"
		   , opts->name, s[0].pkts, s[0].bytes, VTY_NEWLINE);
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

/* Per-program counter print, keyed by selector. Used by the combined view
 * for the breakdown line under each policy. */
void
fswan_bpf_xfrm_policy_counters_by_selector_vty(struct vty *vty,
					       __be32 saddr, __u8 prefixlen_s,
					       __be32 daddr, __u8 prefixlen_d)
{
	struct ipv4_dst_lpm_key dk = {
		.prefixlen	= prefixlen_d,
		.dst		= daddr,
	};
	struct ipv4_policy_lpm_key pk = {
		.prefixlen	= 32 + prefixlen_s,
		.src		= saddr,
	};
	struct ipv4_xfrm_policy val;
	struct fswan_bpf_prog *opts;

	list_for_each_entry(opts, &daemon_data->bpf_progs, next) {
		if (fswan_bpf_xfrm_policy_lookup_in_prog(opts, &dk, &pk, &val))
			continue;
		fswan_bpf_xfrm_policy_counters_vty(vty, opts, &val);
	}
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

/* Per-CPU counter sum for one policy slot. */
static int
fswan_bpf_xfrm_policy_get_counters(struct fswan_bpf_prog *opts, uint32_t slot,
				   uint64_t *pkts_out, uint64_t *bytes_out)
{
	struct bpf_map *map = opts->bpf_maps[FSWAN_BPF_MAP_POLICY_STATS_ARRAY].map;
	unsigned int nr_cpus = libbpf_num_possible_cpus();
	struct xfrm_policy_stats *s;
	unsigned int i;
	int err;

	*pkts_out = *bytes_out = 0;
	if (!slot || slot >= XFRM_POLICY_MAX)
		return -1;

	s = calloc(nr_cpus, sizeof(*s));
	if (!s)
		return -1;

	err = bpf_map__lookup_elem(map, &slot, sizeof(slot),
				   s, nr_cpus * sizeof(*s), 0);
	if (err) {
		free(s);
		return -1;
	}

	for (i = 1; i < nr_cpus; i++) {
		s[0].pkts += s[i].pkts;
		s[0].bytes += s[i].bytes;
	}

	*pkts_out = s[0].pkts;
	*bytes_out = s[0].bytes;
	free(s);
	return 0;
}

/* Counter sum across every program. Returns true when the policy is in
 * any program's LPM map. */
bool
fswan_bpf_xfrm_policy_counters_by_selector_sum(__be32 saddr, __u8 prefixlen_s,
					       __be32 daddr, __u8 prefixlen_d,
					       uint64_t *pkts_out,
					       uint64_t *bytes_out)
{
	struct ipv4_dst_lpm_key dk = {
		.prefixlen	= prefixlen_d,
		.dst		= daddr,
	};
	struct ipv4_policy_lpm_key pk = {
		.prefixlen	= 32 + prefixlen_s,
		.src		= saddr,
	};
	struct ipv4_xfrm_policy val;
	struct fswan_bpf_prog *opts;
	uint64_t pkts = 0, bytes = 0;
	bool found = false;

	list_for_each_entry(opts, &daemon_data->bpf_progs, next) {
		uint64_t p, b;

		if (fswan_bpf_xfrm_policy_lookup_in_prog(opts, &dk, &pk, &val))
			continue;
		found = true;
		if (fswan_bpf_xfrm_policy_get_counters(opts, val.stats_slot, &p, &b))
			continue;
		pkts += p;
		bytes += b;
	}

	*pkts_out = pkts;
	*bytes_out = bytes;
	return found;
}

/* Render every (policy × loaded program) combination as one table row. */
static int
fswan_bpf_xfrm_policy_table_emit(struct vty *vty, struct fswan_bpf_prog *opts,
				 struct table *tbl, bool stats_disabled)
{
	struct bpf_map *map = opts->bpf_maps[FSWAN_BPF_MAP_POLICY_LPM].map;
	struct ipv4_policy_lpm_key key = { 0 }, next_key;
	struct ipv4_xfrm_policy val;
	struct ipv4_dst_lpm_key *dst_table;
	char ifname[IF_NAMESIZE];
	char src[32], dst[32], pkts[24], bytes[24];

	dst_table = calloc(FSWAN_BPF_DST_ID_MAX, sizeof(*dst_table));
	if (!dst_table) {
		vty_out(vty, "%% Cant allocate dst_id table%s", VTY_NEWLINE);
		return -1;
	}
	fswan_bpf_xfrm_dst_table_build(opts, dst_table);

	while (bpf_map__get_next_key(map, &key, &next_key, sizeof(key)) == 0) {
		struct ipv4_dst_lpm_key *dk;
		uint32_t src_bits;
		uint64_t p = 0, b = 0;
		const char *dev;

		key = next_key;
		if (bpf_map__lookup_elem(map, &key, sizeof(key),
					 &val, sizeof(val), 0))
			continue;
		if (key.dst_id >= FSWAN_BPF_DST_ID_MAX)
			continue;

		dk = &dst_table[key.dst_id];
		src_bits = key.prefixlen >= 32 ? key.prefixlen - 32 : 0;

		if (src_bits)
			snprintf(src, sizeof(src), "%u.%u.%u.%u/%u",
				 NIPQUAD(key.src), src_bits);
		else
			snprintf(src, sizeof(src), "0.0.0.0/0");
		snprintf(dst, sizeof(dst), "%u.%u.%u.%u/%u",
			 NIPQUAD(dk->dst), dk->prefixlen);

		dev = if_indextoname(val.ifindex, ifname);
		if (!dev)
			dev = "?";

		if (!stats_disabled)
			fswan_bpf_xfrm_policy_get_counters(opts, val.stats_slot,
							   &p, &b);

		snprintf(pkts, sizeof(pkts), "%lu", (unsigned long) p);
		snprintf(bytes, sizeof(bytes), "%lu", (unsigned long) b);

		table_add_row(tbl, src, dst,
			      (val.flags & XFRM_POLICY_FL_INGRESS) ? "in" : "out",
			      dev, opts->name, pkts, bytes);
	}

	free(dst_table);
	return 0;
}

int
fswan_xfrm_policy_vty(struct vty *vty)
{
	bool stats_disabled = __test_bit(FSWAN_FL_XDP_XFRM_DISABLE_STATS_BIT,
					 &daemon_data->flags);
	struct fswan_bpf_prog *opts;
	struct table *tbl;

	tbl = table_init(7, STYLE_BOLD_TITLE_LIGHT);
	if (!tbl) {
		vty_out(vty, "%% Cant allocate table%s", VTY_NEWLINE);
		return -1;
	}
	table_set_column(tbl, "SRC", "DST", "DIR", "DEV", "PROG", "PKTS", "BYTES");
	table_set_header_align(tbl, ALIGN_CENTER, ALIGN_CENTER, ALIGN_CENTER,
				    ALIGN_CENTER, ALIGN_CENTER, ALIGN_CENTER,
				    ALIGN_CENTER);
	table_set_column_align(tbl, ALIGN_LEFT, ALIGN_LEFT, ALIGN_CENTER,
				    ALIGN_CENTER, ALIGN_CENTER, ALIGN_RIGHT,
				    ALIGN_RIGHT);

	list_for_each_entry(opts, &daemon_data->bpf_progs, next) {
		if (fswan_bpf_xfrm_policy_table_emit(vty, opts, tbl, stats_disabled) < 0) {
			table_destroy(tbl);
			return -1;
		}
	}

	table_vty_out(tbl, vty);
	table_destroy(tbl);
	return 0;
}
