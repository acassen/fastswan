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
#include <errno.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/xfrm.h>

/* local includes */
#include "memory.h"
#include "logger.h"
#include "bitops.h"
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

/* Shared IDR sentinels. Same value across out and in because the kernel
 * IDR is scoped per (chain, prio) and our chains differ between sides. */
#define FLOWER_PROBE_HANDLE	0x7ffffffeU
#define FLOWER_WARMUP_HANDLE	0x7fffffffU

/* Never-match selector used by probe and warmup-pin rules. */
static const struct fswan_flower_sel flower_never_match_sel = {
	.saddr		= 0xffffffff,
	.daddr		= 0xffffffff,
	.prefixlen_s	= 32,
	.prefixlen_d	= 32,
};


/*
 *	Type declarations
 */
struct flower_cache_entry {
	int			ifindex;
	uint16_t		chain;
	struct fswan_flower_sel	sel;
	uint64_t		pkts;
	uint64_t		bytes;
};

struct flower_cache {
	int				n;
	int				cap;
	struct flower_cache_entry	*e;
};

struct flower_cache_build_ctx {
	struct flower_cache	*c;
	int			ifindex;
	uint16_t		chain;
};

struct flower_replay_state {
	int		attempted;
	int		succeeded;
};

struct flower_replay_ctx {
	struct interface	*iface;
	struct flower_replay_state *state;
	int			dir_filter;	/* XFRM_POLICY_OUT or _IN */
};

/* Lives from filter_add_pipelined dispatch until the matching ACK
 * fires the install_done callback. state is NULL on the live path. */
struct flower_pending_install {
	struct fswan_flower_rule	*r;
	struct interface		*iface;
	struct fswan_flower_side	*side;
	struct flower_replay_state	*state;
};


/*
 *	Counter cache, valid only between cache_begin/_end. NULL forces
 *	the per-policy netlink fallback in fswan_flower_policy_counters.
 */
static struct flower_cache *show_cache;


/*
 *	Outbound match-VLAN resolution
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
 *	Inbound two-phase resolver. Two phases so the hard-fail branch
 *	can return before any rb-tree commit, leaving the rule findable
 *	by r->nh_addr when the RTM_NEWNEIGH callback fires. Hairpin tier
 *	mirrors XDP's xfrm_hairpin_xmit shortcut.
 */
static int
flower_resolve_in_prep(struct interface *iface, struct fswan_flower_rule *r)
{
	struct interface *neigh;
	uint32_t gw = 0;
	int oif = 0;

	memcpy(r->src_mac, iface->hw_addr, ETH_ALEN);

	if (iface->hairpin && iface->hairpin->resolved) {
		r->oif		= iface->ifindex;
		r->push_vlan_id	= iface->hairpin->vlan_id;
		r->nh_addr	= iface->hairpin->via_addr;
		return 0;
	}

	if (fswan_netlink_route_lookup(r->sel.daddr, &gw, &oif) < 0) {
		log_message(LOG_INFO, "flower: %s: no route to dst"
				      " %u.%u.%u.%u/%d"
				    , iface->ifname
				    , NIPQUAD(r->sel.daddr), r->sel.prefixlen_d);
		return -1;
	}

	if (oif == iface->ifindex) {
		r->oif		= oif;
		r->push_vlan_id	= 0;
		r->nh_addr	= gw ? gw : r->sel.daddr;
		return 0;
	}

	neigh = fswan_if_get_by_ifindex(oif, true);
	if (neigh && neigh->link_iface == iface) {
		r->oif		= oif;
		r->push_vlan_id	= neigh->vlan_id;
		r->nh_addr	= gw ? gw : r->sel.daddr;
		return 0;
	}

	log_message(LOG_INFO, "flower: %s: dst %u.%u.%u.%u/%d via oif %d is"
			      " neither this iface nor a VLAN child of it"
			    , iface->ifname
			    , NIPQUAD(r->sel.daddr), r->sel.prefixlen_d, oif);
	return -1;
}

static int
flower_resolve_in_neigh(struct interface *iface, struct fswan_flower_rule *r)
{
	if (iface->hairpin && iface->hairpin->resolved) {
		memcpy(r->dst_mac, iface->hairpin->hw_addr, ETH_ALEN);
		return 0;
	}

	/* fswan_flower_neigh_update fills r->dst_mac inline when the
	 * kernel had the LL cached, otherwise the rule parks on -EAGAIN
	 * and the later RTM_NEWNEIGH fires the install. */
	memset(r->dst_mac, 0, ETH_ALEN);
	fswan_netlink_neigh_lookup(r->nh_addr, r->oif);
	return ETHER_IS_ZERO(r->dst_mac) ? -EAGAIN : 0;
}


/*
 *	Rule rbtree helpers, keyed on the selector tuple.
 */
static int
flower_sel_cmp(const struct fswan_flower_sel *a,
	       const struct fswan_flower_sel *b)
{
	if (a->saddr != b->saddr)
		return (a->saddr < b->saddr) ? -1 : 1;
	if (a->daddr != b->daddr)
		return (a->daddr < b->daddr) ? -1 : 1;
	if (a->prefixlen_s != b->prefixlen_s)
		return (a->prefixlen_s < b->prefixlen_s) ? -1 : 1;
	if (a->prefixlen_d != b->prefixlen_d)
		return (a->prefixlen_d < b->prefixlen_d) ? -1 : 1;
	return 0;
}

static int
flower_rule_cmp(const void *key, const struct rb_node *n)
{
	return flower_sel_cmp(key,
		&rb_entry_const(n, struct fswan_flower_rule, node)->sel);
}

static bool
flower_rule_less(struct rb_node *a, const struct rb_node *b)
{
	return flower_sel_cmp(
		&rb_entry(a, struct fswan_flower_rule, node)->sel,
		&rb_entry_const(b, struct fswan_flower_rule, node)->sel) < 0;
}

static struct fswan_flower_rule *
flower_rule_find(struct fswan_flower_side *side, const struct xfrm_policy *p)
{
	const struct fswan_flower_sel key = {
		.saddr		= p->saddr.a4,
		.daddr		= p->daddr.a4,
		.prefixlen_s	= p->prefixlen_s,
		.prefixlen_d	= p->prefixlen_d,
	};
	struct rb_node *n;

	n = rb_find(&key, &side->rules, flower_rule_cmp);
	if (!n)
		return NULL;
	return rb_entry(n, struct fswan_flower_rule, node);
}

static void
flower_rule_init_from_policy(struct fswan_flower_rule *r, uint32_t handle,
			     const struct xfrm_policy *p)
{
	r->handle = handle;
	r->sel.saddr = p->saddr.a4;
	r->sel.daddr = p->daddr.a4;
	r->sel.prefixlen_s = p->prefixlen_s;
	r->sel.prefixlen_d = p->prefixlen_d;
}

static void flower_warmup_pin_out(struct interface *iface, uint16_t vlan_id);
static void flower_warmup_pin_in(struct interface *iface, uint16_t chain,
				 uint16_t push_vlan_id);


/*
 *	Outbound install ACK callback. Rule is not in the rb-tree yet,
 *	so success commits it and failure just frees the allocation.
 */
static void
flower_install_done_out(int err, void *ctx)
{
	struct flower_pending_install *pi = ctx;

	if (err) {
		log_message(LOG_INFO, "flower: %s: skip_sw filter add failed"
				      " for handle:0x%x"
				      " src:%u.%u.%u.%u/%d dst:%u.%u.%u.%u/%d"
				      " (errno=%d %s)"
				    , pi->iface->ifname, pi->r->handle
				    , NIPQUAD(pi->r->sel.saddr)
				    , pi->r->sel.prefixlen_s
				    , NIPQUAD(pi->r->sel.daddr)
				    , pi->r->sel.prefixlen_d
				    , -err, strerror(-err));
		FREE(pi->r);
		goto err;
	}

	rb_add(&pi->r->node, &pi->side->rules, flower_rule_less);
	log_message(LOG_INFO, "flower: flower-xfrm: adding XFRM-Policy="
			      "{src:%u.%u.%u.%u/%d, dst:%u.%u.%u.%u/%d,"
			      " ifindex:%d, dir:out, vlan:%u, handle:0x%x}"
			    , NIPQUAD(pi->r->sel.saddr), pi->r->sel.prefixlen_s
			    , NIPQUAD(pi->r->sel.daddr), pi->r->sel.prefixlen_d
			    , pi->iface->ifindex, pi->r->match_vlan_id
			    , pi->r->handle);
	if (pi->state)
		pi->state->succeeded++;
 err:
	FREE(pi);
}

/*
 *	Inbound install ACK callback. Rule is already in the rb-tree
 *	(committed before the neigh phase), so failure must rb_erase first.
 */
static void
flower_install_done_in(int err, void *ctx)
{
	struct flower_pending_install *pi = ctx;

	if (err) {
		log_message(LOG_INFO, "flower: %s: inbound skip_sw filter add"
				      " failed for handle:0x%x"
				      " src:%u.%u.%u.%u/%d dst:%u.%u.%u.%u/%d"
				      " (errno=%d %s)"
				    , pi->iface->ifname, pi->r->handle
				    , NIPQUAD(pi->r->sel.saddr)
				    , pi->r->sel.prefixlen_s
				    , NIPQUAD(pi->r->sel.daddr)
				    , pi->r->sel.prefixlen_d
				    , -err, strerror(-err));
		rb_erase(&pi->r->node, &pi->side->rules);
		FREE(pi->r);
		goto err;
	}

	log_message(LOG_INFO, "flower: flower-xfrm: adding XFRM-Policy="
			      "{src:%u.%u.%u.%u/%d, dst:%u.%u.%u.%u/%d,"
			      " ifindex:%d, dir:in, push-vlan:%u, handle:0x%x}"
			    , NIPQUAD(pi->r->sel.saddr), pi->r->sel.prefixlen_s
			    , NIPQUAD(pi->r->sel.daddr), pi->r->sel.prefixlen_d
			    , pi->iface->ifindex, pi->r->push_vlan_id
			    , pi->r->handle);
	if (pi->state)
		pi->state->succeeded++;
 err:
	FREE(pi);
}

static int
flower_policy_add_out(struct interface *iface, struct xfrm_policy *p,
		      struct flower_replay_state *state)
{
	struct fswan_flower_side *side = iface->flower->out;
	struct flower_pending_install *pi;
	struct fswan_flower_rule *r;
	uint16_t vlan_id = 0;
	int err;

	/* Idempotent because load-existing-xfrm-policy redispatches a
	 * policy that furious-mode already replayed on this iface. */
	if (flower_rule_find(side, p))
		return 0;
	if (flower_egress_resolve(iface, p, &vlan_id) < 0)
		return -1;

	/* Must precede live rules, otherwise mlx5 extends the flow group
	 * and unbinds live mlx5_fc counters from the periodic refresh. */
	if (!side->warmed_up) {
		flower_warmup_pin_out(iface, vlan_id);
		side->warmed_up = true;
	}

	PMALLOC(r);
	if (!r)
		return -1;
	PMALLOC(pi);
	if (!pi)
		goto err_r;

	flower_rule_init_from_policy(r, side->next_handle++, p);
	r->match_vlan_id = vlan_id;
	pi->r = r;
	pi->iface = iface;
	pi->side = side;
	pi->state = state;

	err = fswan_netlink_flower_filter_add_pipelined(iface->ifindex, 0,
							r->handle, &r->sel,
							r->match_vlan_id,
							iface->ifindex,
							iface->flower->decrement_ttl,
							flower_install_done_out,
							pi);
	if (err) {
		log_message(LOG_INFO, "flower: %s: pipelined send failed"
				      " (err=%d)"
				    , iface->ifname, err);
		goto err_pi;
	}
	return 0;

 err_pi:
	FREE(pi);
 err_r:
	FREE(r);
	return -1;
}

static int
flower_install_in(struct interface *iface, struct fswan_flower_side *side,
		  struct fswan_flower_rule *r,
		  struct flower_replay_state *state)
{
	struct fswan_flower_inbound_args a = {
		.chain		= side->chain,
		.handle		= r->handle,
		.sel		= r->sel,
		.push_vlan_id	= r->push_vlan_id,
		.redirect_ifindex = iface->ifindex,
		.decrement_ttl	= iface->flower->decrement_ttl,
	};
	struct flower_pending_install *pi;
	int ret;

	memcpy(a.dst_mac, r->dst_mac, ETH_ALEN);
	memcpy(a.src_mac, r->src_mac, ETH_ALEN);

	PMALLOC(pi);
	if (!pi)
		return -1;
	pi->r = r;
	pi->iface = iface;
	pi->side = side;
	pi->state = state;

	ret = fswan_netlink_flower_filter_add_in_pipelined(iface->ifindex, &a,
							   flower_install_done_in,
							   pi);
	if (ret) {
		log_message(LOG_INFO, "flower: %s: pipelined in-send failed"
				      " (err=%d)"
				    , iface->ifname, ret);
		FREE(pi);
		return -1;
	}
	return 0;
}

static int
flower_policy_add_in(struct interface *iface, struct xfrm_policy *p,
		     struct flower_replay_state *state)
{
	struct fswan_flower_side *side = iface->flower->in;
	struct fswan_flower_rule *r;
	int ret;

	if (flower_rule_find(side, p))
		return 0;

	PMALLOC(r);
	if (!r)
		return -1;

	flower_rule_init_from_policy(r, side->next_handle++, p);

	if (flower_resolve_in_prep(iface, r) < 0) {
		FREE(r);
		return -1;
	}

	rb_add(&r->node, &side->rules, flower_rule_less);

	if (!side->warmed_up) {
		flower_warmup_pin_in(iface, side->chain, r->push_vlan_id);
		side->warmed_up = true;
	}

	ret = flower_resolve_in_neigh(iface, r);
	if (ret == -EAGAIN) {
		/* Parked, install fires when RTM_NEWNEIGH lands. */
		return 0;
	}

	if (flower_install_in(iface, side, r, state) < 0)
		goto err_erase;
	return 0;

 err_erase:
	rb_erase(&r->node, &side->rules);
	FREE(r);
	return -1;
}

static int
flower_policy_add(struct interface *iface, struct xfrm_policy *p, int dir,
		  struct flower_replay_state *state)
{
	if (dir == XFRM_POLICY_OUT && iface->flower->out)
		return flower_policy_add_out(iface, p, state);
	if (dir == XFRM_POLICY_IN && iface->flower->in)
		return flower_policy_add_in(iface, p, state);
	return 0;
}

static int
flower_policy_del_out(struct interface *iface, struct xfrm_policy *p)
{
	struct fswan_flower_side *side = iface->flower->out;
	struct fswan_flower_rule *r;
	int err;

	/* Commit any in-flight add for this selector so the rb-tree mirrors
	 * the kernel before we look up the rule. */
	fswan_netlink_flower_filter_drain();

	r = flower_rule_find(side, p);
	if (!r)
		return 0;

	err = fswan_netlink_flower_filter_del(iface->ifindex, 0, r->handle);
	if (err)
		log_message(LOG_INFO, "flower: %s: filter del failed for"
				      " handle:0x%x (errno=%d %s)"
				    , iface->ifname, r->handle
				    , -err, strerror(-err));

	rb_erase(&r->node, &side->rules);
	FREE(r);
	return err;
}

static int
flower_policy_del_in(struct interface *iface, struct xfrm_policy *p)
{
	struct fswan_flower_side *side = iface->flower->in;
	struct fswan_flower_rule *r;
	int err;

	fswan_netlink_flower_filter_drain();

	r = flower_rule_find(side, p);
	if (!r)
		return 0;

	err = fswan_netlink_flower_filter_del(iface->ifindex, side->chain,
					      r->handle);
	if (err)
		log_message(LOG_INFO, "flower: %s: inbound filter del failed"
				      " for handle:0x%x (errno=%d %s)"
				    , iface->ifname, r->handle
				    , -err, strerror(-err));

	rb_erase(&r->node, &side->rules);
	FREE(r);
	return err;
}

static int
flower_policy_del(struct interface *iface, struct xfrm_policy *p, int dir)
{
	if (dir == XFRM_POLICY_OUT && iface->flower->out)
		return flower_policy_del_out(iface, p);
	if (dir == XFRM_POLICY_IN && iface->flower->in)
		return flower_policy_del_in(iface, p);
	return 0;
}


/*
 *	Fail flower-mode at enable time if the driver refuses our action
 *	chain. Handle stays in IDR range so del actually removes the rule.
 */
static int
flower_capability_probe_out(struct interface *iface)
{
	int err;

	/* Probe with TTL-dec to exercise the widest action chain. Live
	 * rules drop it when the operator has not opted in. */
	err = fswan_netlink_flower_filter_add(iface->ifindex, 0,
					      FLOWER_PROBE_HANDLE,
					      &flower_never_match_sel, 0,
					      iface->ifindex, true);
	if (err)
		return err;

	err = fswan_netlink_flower_filter_del(iface->ifindex, 0,
					      FLOWER_PROBE_HANDLE);
	if (err)
		log_message(LOG_INFO, "flower: %s: probe rule del failed"
				      " (errno=%d %s)"
				    , iface->ifname, -err, strerror(-err));
	return 0;
}

/*
 *	Inbound probe. Exercises the full action chain at the configured
 *	chain. Failure means the kernel doesnt support post-decrypt feature
 *	or the firmware refuses INSERT_HDR.
 */
static int
flower_capability_probe_in(struct interface *iface, uint16_t chain)
{
	struct fswan_flower_inbound_args a = {
		.chain		= chain,
		.handle		= FLOWER_PROBE_HANDLE,
		.dst_mac	= { 0x02, 0, 0, 0, 0, 0x02 },
		.push_vlan_id	= 1,
		.redirect_ifindex = iface->ifindex,
		.decrement_ttl	= true,
	};
	int err;

	a.sel = flower_never_match_sel;
	memcpy(a.src_mac, iface->hw_addr, ETH_ALEN);

	err = fswan_netlink_flower_filter_add_in(iface->ifindex, &a);
	if (err)
		return err;

	err = fswan_netlink_flower_filter_del(iface->ifindex, chain,
					      FLOWER_PROBE_HANDLE);
	if (err)
		log_message(LOG_INFO, "flower: %s: probe-in rule del failed"
				      " (errno=%d %s)"
				    , iface->ifname, -err, strerror(-err));
	return 0;
}

/* Pin a never-matching rule so the mlx5 hairpin pair keeps a non-zero
 * refcount and skips the around 50ms RSS TTC rebuild on the next install.
 * VLAN matches the first live rule to share its tcf_proto. Caller must
 * install before any live filter, otherwise mlx5 unbinds live mlx5_fc
 * counters when extending the flow group.
 */
static void
flower_warmup_pin_out(struct interface *iface, uint16_t vlan_id)
{
	fswan_netlink_flower_filter_add_pipelined(iface->ifindex, 0,
						  FLOWER_WARMUP_HANDLE,
						  &flower_never_match_sel,
						  vlan_id, iface->ifindex,
						  iface->flower->decrement_ttl,
						  NULL, NULL);
}

/* Inbound warmup-pin. The hairpin pair is scoped per
 * (src_netdev, dst_netdev, chain), so chain-N needs its own pin
 * even when chain-0 is already pinned. push-vlan matches the first
 * live rule to share the mlx5 reformat-insert context. */
static void
flower_warmup_pin_in(struct interface *iface, uint16_t chain,
		     uint16_t push_vlan_id)
{
	struct fswan_flower_inbound_args a = {
		.chain		= chain,
		.handle		= FLOWER_WARMUP_HANDLE,
		.dst_mac	= { 0x02, 0, 0, 0, 0, 0x02 },
		.push_vlan_id	= push_vlan_id,
		.redirect_ifindex = iface->ifindex,
		.decrement_ttl	= iface->flower->decrement_ttl,
	};

	a.sel = flower_never_match_sel;
	memcpy(a.src_mac, iface->hw_addr, ETH_ALEN);
	fswan_netlink_flower_filter_add_in_pipelined(iface->ifindex, &a,
						     NULL, NULL);
}


/*
 *	Replay kernel-side packet-offload policies into the side just enabled,
 *	so SAs already loaded survive activation.
 */
static int
flower_replay_cb(struct xfrm_policy *p, void *ctx)
{
	struct flower_replay_ctx *c = ctx;

	if (p->family != AF_INET)
		return 0;
	if (p->ifindex != c->iface->ifindex)
		return 0;
	if (p->dir != c->dir_filter)
		return 0;

	c->state->attempted++;
	flower_policy_add(c->iface, p, p->dir, c->state);
	return 0;
}

static void
flower_replay_existing(struct interface *iface, int dir)
{
	struct flower_replay_state state = {};
	struct flower_replay_ctx ctx = {
		.iface = iface,
		.state = &state,
		.dir_filter = dir,
	};

	fswan_netlink_xfrm_policy_walk(flower_replay_cb, &ctx);
	fswan_netlink_flower_filter_drain();

	if (state.attempted)
		log_message(LOG_INFO, "flower: %s: replay installed %d/%d %s"
				      " policies"
				    , iface->ifname
				    , state.succeeded, state.attempted
				    , dir == XFRM_POLICY_OUT ? "outbound"
							     : "inbound");
}


/*
 *	Show-counter cache keyed on (ifindex, selector)
 */
static int
flower_cache_cmp(const void *a, const void *b)
{
	const struct flower_cache_entry *ea = a;
	const struct flower_cache_entry *eb = b;

	if (ea->ifindex != eb->ifindex)
		return ea->ifindex - eb->ifindex;
	if (ea->chain != eb->chain)
		return (int)ea->chain - (int)eb->chain;
	return flower_sel_cmp(&ea->sel, &eb->sel);
}

static void
flower_cache_dump_cb(const struct fswan_flower_sel *sel,
		     uint64_t pkts, uint64_t bytes, void *ctx)
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
	e->chain = bc->chain;
	e->sel = *sel;
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
		if (iface->flower->out) {
			bc.chain = 0;
			fswan_netlink_flower_dump(iface->ifindex, 0,
						  flower_cache_dump_cb, &bc);
		}
		if (iface->flower->in) {
			bc.chain = iface->flower->in->chain;
			fswan_netlink_flower_dump(iface->ifindex,
						  iface->flower->in->chain,
						  flower_cache_dump_cb, &bc);
		}
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
flower_cache_lookup(int ifindex, uint16_t chain,
		    const struct fswan_flower_rule *r,
		    uint64_t *pkts, uint64_t *bytes)
{
	struct flower_cache_entry key = {
		.ifindex	= ifindex,
		.chain		= chain,
		.sel		= r->sel,
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
 *	Event hooks. Neigh update/delete are selective (key by nh_addr).
 *	Inbound rebuild is full re-resolve, fired when hairpin or route
 *	inputs flip.
 */
static void
flower_rule_reinstall(struct interface *iface,
		      struct fswan_flower_side *side,
		      struct fswan_flower_rule *r, bool was_installed)
{
	if (was_installed)
		fswan_netlink_flower_filter_del(iface->ifindex, side->chain,
						r->handle);
	flower_install_in(iface, side, r, NULL);
}

static void
flower_neigh_update_iface(struct interface *iface, uint32_t addr,
			  const uint8_t *lladdr)
{
	struct fswan_flower_side *side = iface->flower->in;
	struct fswan_flower_rule *r;
	bool was_installed;

	rb_for_each_entry(r, &side->rules, node) {
		if (r->nh_addr != addr)
			continue;
		was_installed = !ETHER_IS_ZERO(r->dst_mac);
		if (was_installed &&
		    memcmp(r->dst_mac, lladdr, ETH_ALEN) == 0)
			continue;
		memcpy(r->dst_mac, lladdr, ETH_ALEN);
		flower_rule_reinstall(iface, side, r, was_installed);
	}
}

void
fswan_flower_neigh_update(uint32_t addr, const uint8_t *lladdr,
			  __attribute__((unused)) int ifindex)
{
	struct interface *iface;

	list_for_each_entry(iface, &daemon_data->interfaces, next)
		if (iface->flower && iface->flower->in)
			flower_neigh_update_iface(iface, addr, lladdr);
}

static void
flower_neigh_delete_iface(struct interface *iface, uint32_t addr)
{
	struct fswan_flower_side *side = iface->flower->in;
	struct fswan_flower_rule *r;

	rb_for_each_entry(r, &side->rules, node) {
		if (r->nh_addr != addr)
			continue;
		if (ETHER_IS_ZERO(r->dst_mac))
			continue;
		fswan_netlink_flower_filter_del(iface->ifindex, side->chain,
						r->handle);
		memset(r->dst_mac, 0, ETH_ALEN);
	}
}

void
fswan_flower_neigh_delete(uint32_t addr)
{
	struct interface *iface;

	list_for_each_entry(iface, &daemon_data->interfaces, next)
		if (iface->flower && iface->flower->in)
			flower_neigh_delete_iface(iface, addr);
}

void
fswan_flower_inbound_rebuild(struct interface *iface)
{
	struct fswan_flower_side *side;
	struct fswan_flower_rule *r;
	uint8_t old_dst[ETH_ALEN];
	uint16_t old_push_vlan;
	bool was_installed;

	if (!iface->flower || !iface->flower->in)
		return;
	side = iface->flower->in;

	rb_for_each_entry(r, &side->rules, node) {
		memcpy(old_dst, r->dst_mac, ETH_ALEN);
		old_push_vlan = r->push_vlan_id;
		was_installed = !ETHER_IS_ZERO(old_dst);

		if (flower_resolve_in_prep(iface, r) < 0) {
			if (was_installed) {
				fswan_netlink_flower_filter_del(iface->ifindex,
								side->chain,
								r->handle);
				memset(r->dst_mac, 0, ETH_ALEN);
			}
			continue;
		}

		memset(r->dst_mac, 0, ETH_ALEN);
		if (flower_resolve_in_neigh(iface, r) == -EAGAIN) {
			if (was_installed)
				fswan_netlink_flower_filter_del(iface->ifindex,
								side->chain,
								r->handle);
			continue;
		}

		if (was_installed &&
		    old_push_vlan == r->push_vlan_id &&
		    memcmp(old_dst, r->dst_mac, ETH_ALEN) == 0)
			continue;

		flower_rule_reinstall(iface, side, r, was_installed);
	}
}


/*
 *	Wrapper lifecycle. clsact and the mlx5 driver check are wrapper-scoped,
 *	so iface->flower comes up with the first active side and goes away
 *	with the last.
 */
static int
flower_wrapper_ensure(struct interface *iface)
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
		log_message(LOG_INFO, "flower: %s: driver '%s' is not '%s',"
				      " refusing flower offload"
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

	PMALLOC(iface->flower);
	if (!iface->flower) {
		fswan_netlink_flower_clsact(iface->ifindex, false);
		return -1;
	}
	return 0;
}

static void
flower_wrapper_release(struct interface *iface)
{
	fswan_netlink_flower_clsact(iface->ifindex, false);
	FREE(iface->flower);
	iface->flower = NULL;
}

static void
flower_wrapper_release_if_empty(struct interface *iface)
{
	if (iface->flower->out || iface->flower->in)
		return;
	flower_wrapper_release(iface);
}

int
fswan_flower_enable_out(struct interface *iface)
{
	int err;

	if (iface->flower && iface->flower->out)
		return 0;

	if (flower_wrapper_ensure(iface) < 0)
		return -1;

	err = flower_capability_probe_out(iface);
	if (err) {
		log_message(LOG_INFO, "flower: %s: outbound probe failed"
				      " (errno=%d %s)"
				    , iface->ifname, -err, strerror(-err));
		flower_wrapper_release_if_empty(iface);
		return -1;
	}

	PMALLOC(iface->flower->out);
	if (!iface->flower->out) {
		flower_wrapper_release_if_empty(iface);
		return -1;
	}
	iface->flower->out->next_handle = 1;
	log_message(LOG_INFO, "flower: %s: outbound HW offload active"
			    , iface->ifname);

	flower_replay_existing(iface, XFRM_POLICY_OUT);
	return 0;
}

int
fswan_flower_enable_in(struct interface *iface, uint16_t chain)
{
	int err;

	if (iface->flower && iface->flower->in)
		return 0;

	if (flower_wrapper_ensure(iface) < 0)
		return -1;

	err = flower_capability_probe_in(iface, chain);
	if (err) {
		log_message(LOG_INFO, "flower: %s: post-decrypt probe failed"
				      " (errno=%d %s)"
				    , iface->ifname, -err, strerror(-err));
		flower_wrapper_release_if_empty(iface);
		return -1;
	}

	PMALLOC(iface->flower->in);
	if (!iface->flower->in) {
		flower_wrapper_release_if_empty(iface);
		return -1;
	}
	iface->flower->in->next_handle = 1;
	iface->flower->in->chain = chain;
	log_message(LOG_INFO, "flower: %s: inbound HW offload active"
			      " (post-decrypt chain %u)"
			    , iface->ifname, chain);

	flower_replay_existing(iface, XFRM_POLICY_IN);
	return 0;
}

static void
flower_side_cleanup(struct interface *iface, struct fswan_flower_side *side)
{
	struct fswan_flower_rule *r, *tmp;

	rb_for_each_entry_safe(r, tmp, &side->rules, node) {
		fswan_netlink_flower_filter_del(iface->ifindex, side->chain,
						r->handle);
		rb_erase(&r->node, &side->rules);
		FREE(r);
	}
}

/* Drain pending install ACKs first because their callbacks would rb_add
 * into the tree we are about to walk. */
static void
flower_disable_side(struct interface *iface,
		    struct fswan_flower_side **side_pp)
{
	if (!*side_pp)
		return;
	fswan_netlink_flower_filter_drain();
	flower_side_cleanup(iface, *side_pp);
	FREE(*side_pp);
	*side_pp = NULL;
}

void
fswan_flower_disable_out(struct interface *iface)
{
	if (!iface->flower)
		return;
	flower_disable_side(iface, &iface->flower->out);
	flower_wrapper_release_if_empty(iface);
}

void
fswan_flower_disable_in(struct interface *iface)
{
	if (!iface->flower)
		return;
	flower_disable_side(iface, &iface->flower->in);
	flower_wrapper_release_if_empty(iface);
}

void
fswan_flower_disable(struct interface *iface)
{
	fswan_flower_disable_out(iface);
	fswan_flower_disable_in(iface);
}

int
fswan_flower_xfrm_action(int action, struct interface *iface,
			 struct xfrm_policy *p)
{
	int dir = __test_bit(XFRM_POLICY_FL_OUT_BIT, &p->flags)
		  ? XFRM_POLICY_OUT
		  : XFRM_POLICY_IN;

	if (action == XFRM_MSG_NEWPOLICY)
		return flower_policy_add(iface, p, dir, NULL);
	if (action == XFRM_MSG_DELPOLICY)
		return flower_policy_del(iface, p, dir);
	return 0;
}

bool
fswan_flower_policy_counters(struct interface *iface,
			     const struct xfrm_policy *p,
			     uint64_t *pkts, uint64_t *bytes)
{
	struct fswan_flower_side *side;
	struct fswan_flower_rule *r;

	*pkts = 0;
	*bytes = 0;

	if (!iface->flower)
		return false;

	if (p->dir == XFRM_POLICY_OUT && iface->flower->out)
		side = iface->flower->out;
	else if (p->dir == XFRM_POLICY_IN && iface->flower->in)
		side = iface->flower->in;
	else
		return false;

	r = flower_rule_find(side, p);
	if (!r)
		return false;

	if (flower_cache_lookup(iface->ifindex, side->chain, r, pkts, bytes))
		return true;

	fswan_netlink_flower_filter_stats(iface->ifindex, side->chain,
					  r->handle, pkts, bytes);
	return true;
}
