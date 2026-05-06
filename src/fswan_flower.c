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
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/xfrm.h>

/* local includes */
#include "memory.h"
#include "logger.h"
#include "rbtree_api.h"
#include "ethtool.h"
#include "inet_utils.h"
#include "fswan_data.h"
#include "fswan_if.h"
#include "fswan_netlink.h"
#include "fswan_netlink_flower.h"
#include "fswan_flower.h"


/* Extern data */
extern struct data *daemon_data;

#define FLOWER_DRIVER_MLX5	"mlx5_core"


/*
 *	Type declarations
 */
struct flower_rule_key {
	__be32		saddr;
	__be32		daddr;
	uint8_t		prefixlen_s;
	uint8_t		prefixlen_d;
};

struct flower_cache_entry {
	int		ifindex;
	uint32_t	handle;
	uint64_t	pkts;
	uint64_t	bytes;
};

struct flower_cache {
	int				n;
	int				cap;
	struct flower_cache_entry	*e;
};

struct flower_cache_build_ctx {
	struct flower_cache	*c;
	int			ifindex;
};

struct flower_replay_state {
	int		attempted;
	int		succeeded;
};

struct flower_replay_ctx {
	struct interface	*iface;
	struct flower_replay_state *state;
};

/* Per pipelined-install pending. lives from filter_add_pipelined
 * dispatch until the matching ACK fires the install_done callback. */
struct flower_replay_pending {
	struct fswan_flower_rule	*r;
	struct interface		*iface;
	struct flower_replay_state	*state;
};


/*
 *	show-counter cache. (NULL outside cache_begin/_end pairs)
 *	fswan_flower_policy_counters consults it before
 *	falling back to per-policy netlink.
 */
static struct flower_cache *show_cache;


/*
 *	Egress resolution
 */
static int
flower_egress_resolve(struct interface *iface, struct xfrm_policy *p,
		      uint16_t *vlan_id_out)
{
	struct interface *neigh;
	uint32_t gw = 0;
	int oif = 0;

	*vlan_id_out = 0;

	if (fswan_netlink_route_lookup(p->saddr.a4, &gw, &oif) < 0) {
		log_message(LOG_INFO, "flower: %s: no route to source"
				      " %u.%u.%u.%u/%d"
				    , iface->ifname
				    , NIPQUAD(p->saddr.a4), p->prefixlen_s);
		return -1;
	}

	if (oif == iface->ifindex)
		return 0;

	neigh = fswan_if_get_by_ifindex(oif, true);
	if (neigh && neigh->link_iface == iface) {
		*vlan_id_out = neigh->vlan_id;
		return 0;
	}

	log_message(LOG_INFO, "flower: %s: route to %u.%u.%u.%u/%d via oif %d"
			      " is neither this iface nor a VLAN child of it"
			    , iface->ifname
			    , NIPQUAD(p->saddr.a4), p->prefixlen_s, oif);
	return -1;
}


/*
 *	Rule rbtree helpers
 */
static int
flower_rule_key_cmp(const struct flower_rule_key *k,
		    const struct fswan_flower_rule *r)
{
	if (k->saddr != r->saddr)
		return (k->saddr < r->saddr) ? -1 : 1;
	if (k->daddr != r->daddr)
		return (k->daddr < r->daddr) ? -1 : 1;
	if (k->prefixlen_s != r->prefixlen_s)
		return (k->prefixlen_s < r->prefixlen_s) ? -1 : 1;
	if (k->prefixlen_d != r->prefixlen_d)
		return (k->prefixlen_d < r->prefixlen_d) ? -1 : 1;
	return 0;
}

static int
flower_rule_cmp(const void *key, const struct rb_node *n)
{
	return flower_rule_key_cmp(key,
		rb_entry_const(n, struct fswan_flower_rule, node));
}

static bool
flower_rule_less(struct rb_node *a, const struct rb_node *b)
{
	const struct fswan_flower_rule *ra =
		rb_entry(a, struct fswan_flower_rule, node);
	const struct flower_rule_key key = {
		.saddr		= ra->saddr,
		.daddr		= ra->daddr,
		.prefixlen_s	= ra->prefixlen_s,
		.prefixlen_d	= ra->prefixlen_d,
	};

	return flower_rule_key_cmp(&key,
		rb_entry_const(b, struct fswan_flower_rule, node)) < 0;
}

static struct fswan_flower_rule *
flower_rule_find(struct interface *iface, const struct xfrm_policy *p)
{
	const struct flower_rule_key key = {
		.saddr		= p->saddr.a4,
		.daddr		= p->daddr.a4,
		.prefixlen_s	= p->prefixlen_s,
		.prefixlen_d	= p->prefixlen_d,
	};
	struct rb_node *n;

	n = rb_find(&key, &iface->flower->rules, flower_rule_cmp);
	if (!n)
		return NULL;
	return rb_entry(n, struct fswan_flower_rule, node);
}

static void
flower_rule_init_from_policy(struct fswan_flower_rule *r, uint32_t handle,
			     uint16_t vlan_id, const struct xfrm_policy *p)
{
	r->handle = handle;
	r->saddr = p->saddr.a4;
	r->daddr = p->daddr.a4;
	r->prefixlen_s = p->prefixlen_s;
	r->prefixlen_d = p->prefixlen_d;
	r->vlan_id = vlan_id;
}

static void
flower_log_installed(const struct interface *iface,
		     const struct fswan_flower_rule *r)
{
	log_message(LOG_INFO, "flower: flower-xfrm: adding XFRM-Policy="
			      "{src:%u.%u.%u.%u/%d, dst:%u.%u.%u.%u/%d,"
			      " ifindex:%d, dir:out, vlan:%u, handle:0x%x}"
			    , NIPQUAD(r->saddr), r->prefixlen_s
			    , NIPQUAD(r->daddr), r->prefixlen_d
			    , iface->ifindex, r->vlan_id, r->handle);
}

static void
flower_rule_to_sel(const struct fswan_flower_rule *r,
		   struct fswan_flower_sel *sel)
{
	sel->saddr = r->saddr;
	sel->daddr = r->daddr;
	sel->prefixlen_s = r->prefixlen_s;
	sel->prefixlen_d = r->prefixlen_d;
}


/*
 *	Policy helpers
 */
static int
flower_policy_add(struct interface *iface, struct xfrm_policy *p)
{
	struct fswan_flower_rule *r;
	struct fswan_flower_sel sel;
	uint16_t vlan_id = 0;
	uint32_t handle;
	int err;

	/* a NEWPOLICY arriving via load-existing-xfrm-policy after
	 * furious-mode already replayed it on this iface is expected.
	 */
	if (flower_rule_find(iface, p))
		return 0;

	if (flower_egress_resolve(iface, p, &vlan_id) < 0)
		return -1;

	PMALLOC(r);
	if (!r)
		return -1;

	handle = iface->flower->next_handle++;
	flower_rule_init_from_policy(r, handle, vlan_id, p);
	flower_rule_to_sel(r, &sel);

	err = fswan_netlink_flower_filter_add(iface->ifindex, handle, &sel,
					      vlan_id, iface->ifindex);
	if (err) {
		log_message(LOG_INFO, "flower: %s: skip_sw filter add failed"
				      " for src:%u.%u.%u.%u/%d dst:%u.%u.%u.%u/%d"
				      " (errno=%d %s)"
				    , iface->ifname
				    , NIPQUAD(p->saddr.a4), p->prefixlen_s
				    , NIPQUAD(p->daddr.a4), p->prefixlen_d
				    , -err, strerror(-err));
		FREE(r);
		return -1;
	}

	rb_add(&r->node, &iface->flower->rules, flower_rule_less);
	flower_log_installed(iface, r);
	return 0;
}

static int
flower_policy_del(struct interface *iface, struct xfrm_policy *p)
{
	struct fswan_flower_rule *r;
	int err;

	r = flower_rule_find(iface, p);
	if (!r)
		return 0;

	err = fswan_netlink_flower_filter_del(iface->ifindex, r->handle);
	if (err)
		log_message(LOG_INFO, "flower: %s: filter del failed for"
				      " handle:0x%x (errno=%d %s)"
				    , iface->ifname, r->handle
				    , -err, strerror(-err));

	rb_erase(&r->node, &iface->flower->rules);
	FREE(r);
	return err;
}


/*
 *	Capability probe
 */
static int
flower_capability_probe(struct interface *iface)
{
	struct fswan_flower_sel sel = {
		.saddr		= 0xffffffff,	/* 255.255.255.255 */
		.daddr		= 0xffffffff,
		.prefixlen_s	= 32,
		.prefixlen_d	= 32,
	};
	const uint32_t probe_handle = 0xfffffffeU;
	int err;

	err = fswan_netlink_flower_filter_add(iface->ifindex, probe_handle,
					      &sel, 0, iface->ifindex);
	if (err)
		return err;

	err = fswan_netlink_flower_filter_del(iface->ifindex, probe_handle);
	if (err)
		log_message(LOG_INFO, "flower: %s: probe rule del failed"
				      " (errno=%d %s)"
				    , iface->ifname, -err, strerror(-err));
	return 0;
}


/*
 *	When flower-mode is enabled on an iface that already has SAs/policies
 *	loaded, walk the kernel's policy table and install every matching
 *	outbound packet-offload policy.
 */
static void
flower_replay_install_done(int err, void *ctx)
{
	struct flower_replay_pending *pi = ctx;

	if (err) {
		log_message(LOG_INFO, "flower: %s: skip_sw filter add failed"
				      " for handle:0x%x"
				      " src:%u.%u.%u.%u/%d dst:%u.%u.%u.%u/%d"
				      " (errno=%d %s)"
				    , pi->iface->ifname, pi->r->handle
				    , NIPQUAD(pi->r->saddr), pi->r->prefixlen_s
				    , NIPQUAD(pi->r->daddr), pi->r->prefixlen_d
				    , -err, strerror(-err));
		FREE(pi->r);
	} else {
		rb_add(&pi->r->node, &pi->iface->flower->rules,
		       flower_rule_less);
		flower_log_installed(pi->iface, pi->r);
		pi->state->succeeded++;
	}
	FREE(pi);
}

static int
flower_policy_add_pipelined(struct interface *iface, struct xfrm_policy *p,
			    struct flower_replay_state *state)
{
	struct flower_replay_pending *pi;
	struct fswan_flower_rule *r;
	struct fswan_flower_sel sel;
	uint16_t vlan_id = 0;
	uint32_t handle;
	int err;

	if (flower_rule_find(iface, p))
		return -1;
	if (flower_egress_resolve(iface, p, &vlan_id) < 0)
		return -1;

	PMALLOC(r);
	if (!r)
		return -1;
	PMALLOC(pi);
	if (!pi) {
		FREE(r);
		return -1;
	}

	handle = iface->flower->next_handle++;
	flower_rule_init_from_policy(r, handle, vlan_id, p);
	flower_rule_to_sel(r, &sel);

	pi->r = r;
	pi->iface = iface;
	pi->state = state;

	err = fswan_netlink_flower_filter_add_pipelined(iface->ifindex, handle,
							&sel, vlan_id,
							iface->ifindex,
							flower_replay_install_done,
							pi);
	if (err) {
		log_message(LOG_INFO, "flower: %s: pipelined send failed"
				      " (err=%d)"
				    , iface->ifname, err);
		FREE(pi);
		FREE(r);
		return -1;
	}
	return 0;
}

static int
flower_replay_cb(struct xfrm_policy *p, void *ctx)
{
	struct flower_replay_ctx *c = ctx;

	if (p->family != AF_INET)
		return 0;
	if (p->ifindex != c->iface->ifindex)
		return 0;
	if (p->dir != XFRM_POLICY_OUT)
		return 0;

	c->state->attempted++;
	flower_policy_add_pipelined(c->iface, p, c->state);
	return 0;
}

static void
flower_replay_existing(struct interface *iface)
{
	struct flower_replay_state state = {};
	struct flower_replay_ctx ctx = {
		.iface = iface,
		.state = &state,
	};

	fswan_netlink_xfrm_policy_walk(flower_replay_cb, &ctx);
	fswan_netlink_flower_filter_drain();

	if (state.attempted)
		log_message(LOG_INFO, "flower: %s: replay installed %d/%d"
				      " outbound policies"
				    , iface->ifname
				    , state.succeeded, state.attempted);
}


/*
 *	Show-counter cache
 */
static int
flower_cache_cmp(const void *a, const void *b)
{
	const struct flower_cache_entry *ea = a;
	const struct flower_cache_entry *eb = b;

	if (ea->ifindex != eb->ifindex)
		return ea->ifindex - eb->ifindex;
	if (ea->handle < eb->handle)
		return -1;
	if (ea->handle > eb->handle)
		return 1;
	return 0;
}

static void
flower_cache_dump_cb(uint32_t handle, uint64_t pkts, uint64_t bytes,
		     void *ctx)
{
	struct flower_cache_build_ctx *bc = ctx;
	struct flower_cache *c = bc->c;
	struct flower_cache_entry *e;
	int new_cap;

	if (c->n == c->cap) {
		new_cap = c->cap ? c->cap * 2 : 64;
		e = REALLOC(c->e, new_cap * sizeof(*e));
		if (!e)
			return;
		c->e = e;
		c->cap = new_cap;
	}

	e = &c->e[c->n++];
	e->ifindex = bc->ifindex;
	e->handle = handle;
	e->pkts = pkts;
	e->bytes = bytes;
}

void
fswan_flower_counter_cache_begin(void)
{
	struct flower_cache_build_ctx bc;
	struct interface *iface;
	struct flower_cache *c;

	if (show_cache)
		return;

	c = MALLOC(sizeof(*c));
	if (!c)
		return;

	bc.c = c;
	list_for_each_entry(iface, &daemon_data->interfaces, next) {
		if (!iface->flower)
			continue;
		bc.ifindex = iface->ifindex;
		fswan_netlink_flower_dump(iface->ifindex,
					  flower_cache_dump_cb, &bc);
	}

	if (c->n > 1)
		qsort(c->e, c->n, sizeof(*c->e), flower_cache_cmp);
	show_cache = c;
}

void
fswan_flower_counter_cache_end(void)
{
	if (!show_cache)
		return;
	if (show_cache->e)
		FREE(show_cache->e);
	FREE(show_cache);
	show_cache = NULL;
}

static bool
flower_cache_lookup(int ifindex, uint32_t handle,
		    uint64_t *pkts, uint64_t *bytes)
{
	struct flower_cache_entry key = {
		.ifindex = ifindex,
		.handle = handle,
	};
	struct flower_cache_entry *found;

	if (!show_cache || !show_cache->n)
		return false;

	found = bsearch(&key, show_cache->e, show_cache->n,
			sizeof(*show_cache->e), flower_cache_cmp);
	if (!found)
		return false;

	*pkts = found->pkts;
	*bytes = found->bytes;
	return true;
}


/*
 *	Helpers
 */
int
fswan_flower_enable(struct interface *iface)
{
	char driver[32];
	int err;

	if (iface->flower)
		return 0;

	if (ethtool_get_driver_name(iface->ifname, driver, sizeof(driver))) {
		log_message(LOG_INFO, "flower: %s: cannot read driver name"
				    , iface->ifname);
		return -1;
	}
	if (strcmp(driver, FLOWER_DRIVER_MLX5)) {
		log_message(LOG_INFO, "flower: %s: driver '%s' is not '%s'"
				      ", refusing flower-mode"
				    , iface->ifname, driver, FLOWER_DRIVER_MLX5);
		return -1;
	}

	fswan_netlink_flower_clsact(iface->ifindex, false);
	err = fswan_netlink_flower_clsact(iface->ifindex, true);
	if (err) {
		log_message(LOG_INFO, "flower: %s: clsact add failed"
				      " (errno=%d %s)"
				    , iface->ifname, -err, strerror(-err));
		return -1;
	}

	err = flower_capability_probe(iface);
	if (err) {
		log_message(LOG_INFO, "flower: %s: capability probe failed"
				      " (errno=%d %s)"
				    , iface->ifname, -err, strerror(-err));
		fswan_netlink_flower_clsact(iface->ifindex, false);
		return -1;
	}

	PMALLOC(iface->flower);
	if (!iface->flower) {
		fswan_netlink_flower_clsact(iface->ifindex, false);
		return -1;
	}
	iface->flower->next_handle = 1;
	/* PMALLOC zeroes the rb_root; nothing else to init. */

	flower_replay_existing(iface);
	return 0;
}

void
fswan_flower_disable(struct interface *iface)
{
	struct fswan_flower_rule *r, *tmp;

	if (!iface->flower)
		return;

	/* Pending install ACK whose cb would rb_add into the
	 * rules tree must not race the teardown traversal.
	 */
	fswan_netlink_flower_filter_drain();

	rb_for_each_entry_safe(r, tmp, &iface->flower->rules, node) {
		fswan_netlink_flower_filter_del(iface->ifindex, r->handle);
		rb_erase(&r->node, &iface->flower->rules);
		FREE(r);
	}

	fswan_netlink_flower_clsact(iface->ifindex, false);
	FREE(iface->flower);
	iface->flower = NULL;
}

int
fswan_flower_xfrm_action(int action, struct interface *iface,
			 struct xfrm_policy *p)
{
	if (action == XFRM_MSG_NEWPOLICY)
		return flower_policy_add(iface, p);
	if (action == XFRM_MSG_DELPOLICY)
		return flower_policy_del(iface, p);
	return 0;
}

bool
fswan_flower_policy_counters(struct interface *iface,
			     const struct xfrm_policy *p,
			     uint64_t *pkts, uint64_t *bytes)
{
	struct fswan_flower_rule *r;

	*pkts = 0;
	*bytes = 0;

	if (!iface->flower)
		return false;

	r = flower_rule_find(iface, p);
	if (!r)
		return false;

	if (flower_cache_lookup(iface->ifindex, r->handle, pkts, bytes))
		return true;

	fswan_netlink_flower_filter_stats(iface->ifindex, r->handle,
					  pkts, bytes);
	return true;
}
