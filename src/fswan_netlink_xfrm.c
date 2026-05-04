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
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>

/* local includes */
#include "logger.h"
#include "bitops.h"
#include "utils.h"
#include "thread.h"
#include "fswan_data.h"
#include "fswan_netlink.h"
#include "fswan_bpf_xfrm.h"

/* Local data */
static struct nl_handle nl_kernel = { .fd = -1 };	/* XFRM reflection channel */

/* Extern data */
extern struct data *daemon_data;
extern struct thread_master *master;

/* Ok this is a nasty hack but PACKET OFFLOAD is not part of all distros.
 * otherwise need to maintain a uapi copy like iproute2 does */
#ifndef XFRM_OFFLOAD_PACKET
#define XFRM_OFFLOAD_PACKET	4
#endif


/*
 *	Type declarations
 */
struct sa_walk_ctx {
	xfrm_sa_walk_cb		user_cb;
	void			*user_ctx;
	uint32_t		flags;
};

struct policy_walk_ctx {
	xfrm_policy_walk_cb	user_cb;
	void			*user_ctx;
};

static const char *
get_nl_msg_type(unsigned type)
{
	switch (type) {
		switch_define_str(XFRM_MSG_NEWSA);
		switch_define_str(XFRM_MSG_DELSA);
		switch_define_str(XFRM_MSG_UPDSA);
		switch_define_str(XFRM_MSG_EXPIRE);
		switch_define_str(XFRM_MSG_NEWPOLICY);
		switch_define_str(XFRM_MSG_DELPOLICY);
		switch_define_str(XFRM_MSG_UPDPOLICY);
		switch_define_str(XFRM_MSG_POLEXPIRE);
		switch_define_str(XFRM_MSG_ACQUIRE);
		switch_define_str(XFRM_MSG_FLUSHSA);
		switch_define_str(XFRM_MSG_FLUSHPOLICY);
		switch_define_str(XFRM_MSG_REPORT);
		switch_define_str(XFRM_MSG_NEWAE);
		switch_define_str(XFRM_MSG_MAPPING);
	};

	return "";
}


/*
 *	Kernel Netlink reflector
 */

/* This one is mostly coming from iproute2 code */
static int
xfrm_policy_filter(struct nlmsghdr *n)
{
	struct rtattr *tb[XFRMA_MAX+1];
	struct rtattr *rta;
	struct xfrm_userpolicy_info *xpinfo = NULL;
	struct xfrm_user_polexpire *xpexp = NULL;
	struct xfrm_userpolicy_id *xpid = NULL;
	struct xfrm_selector *sel;
	struct xfrm_user_offload *xuo;
	struct xfrm_policy policy;
	int len = n->nlmsg_len;

	if (n->nlmsg_type == XFRM_MSG_DELPOLICY)  {
		xpid = NLMSG_DATA(n);
		len -= NLMSG_SPACE(sizeof(*xpid));
	} else if (n->nlmsg_type == XFRM_MSG_POLEXPIRE) {
		xpexp = NLMSG_DATA(n);
		xpinfo = &xpexp->pol;
		len -= NLMSG_SPACE(sizeof(*xpexp));
	} else {
		xpexp = NULL;
		xpinfo = NLMSG_DATA(n);
		len -= NLMSG_SPACE(sizeof(*xpinfo));
	}

	if (len < 0) {
		log_message(LOG_INFO, "%s(): BUG: wrong nlmsg len %d"
				    , __FUNCTION__, len);
		return -1;
	}

	if (n->nlmsg_type == XFRM_MSG_DELPOLICY)
		rta = XFRMPID_RTA(xpid);
	else if (n->nlmsg_type == XFRM_MSG_POLEXPIRE)
		rta = XFRMPEXP_RTA(xpexp);
	else
		rta = XFRMP_RTA(xpinfo);

	parse_rtattr(tb, XFRMA_MAX, rta, len);

	if (n->nlmsg_type == XFRM_MSG_DELPOLICY) {
		if (!tb[XFRMA_POLICY]) {
			log_message(LOG_INFO, "%s(): Buggy XFRM_MSG_DELPOLICY: no XFRMA_POLICY"
					    , __FUNCTION__);
			return -1;
		}
		if (RTA_PAYLOAD(tb[XFRMA_POLICY]) < sizeof(*xpinfo)) {
			log_message(LOG_INFO, "%s(): Buggy XFRM_MSG_DELPOLICY: too short XFRMA_POLICY len"
					    , __FUNCTION__);
			return -1;
		}
		xpinfo = RTA_DATA(tb[XFRMA_POLICY]);
	}

	/* Only take into account IN & OUT (also rejects socket-bound dirs). */
	if (!(xpinfo->dir == XFRM_POLICY_IN || xpinfo->dir == XFRM_POLICY_OUT))
		return 0;

	/* Only offload is considered */
	if (!tb[XFRMA_OFFLOAD_DEV])
		return 0;

	if (RTA_PAYLOAD(tb[XFRMA_OFFLOAD_DEV]) < sizeof(*xuo)) {
		log_message(LOG_INFO, "%s(): Truncated xfrm Offload info"
				    , __FUNCTION__);
		return -1;
	}

	xuo = (struct xfrm_user_offload *) RTA_DATA(tb[XFRMA_OFFLOAD_DEV]);

	/* Only Packet offload is supported */
	if (!(xuo->flags & XFRM_OFFLOAD_PACKET))
		return 0;

	/* Skip protocol specific policy */
	sel = &xpinfo->sel;
	if (sel->proto)
		return 0;

	/* Cherry pick */
	memset(&policy, 0, sizeof(struct xfrm_policy));
	policy.family = sel->family;
	policy.daddr = sel->daddr;
	policy.saddr = sel->saddr;
	policy.prefixlen_d = sel->prefixlen_d;
	policy.prefixlen_s = sel->prefixlen_s;
	policy.ifindex = xuo->ifindex;
	__set_bit((xpinfo->dir == XFRM_POLICY_IN) ? XFRM_POLICY_FL_IN_BIT : XFRM_POLICY_FL_OUT_BIT
		  , &policy.flags);

	return fswan_bpf_xfrm_action(n->nlmsg_type, &policy);
}

static int
netlink_xfrm_filter(__attribute__((unused)) struct sockaddr_nl *snl,
		    struct nlmsghdr *h,
		    __attribute__((unused)) void *userdata)
{
	switch (h->nlmsg_type) {
	case XFRM_MSG_NEWPOLICY:
	case XFRM_MSG_DELPOLICY:
	case XFRM_MSG_UPDPOLICY:
	case XFRM_MSG_POLEXPIRE:
		return xfrm_policy_filter(h);
	default:
		log_message(LOG_INFO, "Kernel is reflecting an unknown netlink nlmsg_type: %s(%u)"
				    , get_nl_msg_type(h->nlmsg_type), h->nlmsg_type);
	}
	return 0;
}


/*
 *	Kernel Netlink reflector reactor
 */
static void
kernel_netlink(struct thread *thread)
{
	struct nl_handle *nl = THREAD_ARG(thread);

	if (thread->type != THREAD_READ_TIMEOUT)
		netlink_parse_info(netlink_xfrm_filter, nl, NULL, true);

	nl->thread = thread_add_read(master, kernel_netlink, nl, nl->fd, TIMER_NEVER, 0);
}


/*
 *	Netlink XFRM lookup
 */
static int
netlink_xfrm_request(struct nl_handle *nl, uint16_t type)
{
	struct sockaddr_nl snl = { .nl_family = AF_NETLINK };
	struct nlmsghdr nlh = {
		.nlmsg_len = NLMSG_HDRLEN,
		.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
		.nlmsg_type = type,
		.nlmsg_seq = ++nl->seq,
	};

	if (sendto(nl->fd, &nlh, sizeof(nlh), 0,
		   (struct sockaddr *) &snl, sizeof(snl)) < 0) {
		log_message(LOG_INFO, "Netlink: sendto() failed: %m");
		return -1;
	}

	return 0;
}

static int
netlink_xfrm_dump(uint16_t type,
		  int (*cb)(struct sockaddr_nl *, struct nlmsghdr *, void *),
		  void *ctx)
{
	struct nl_handle nl = { .fd = -1 };
	int err = 0;

	err = netlink_open(&nl, daemon_data->nl_rcvbuf_size, SOCK_NONBLOCK,
			   NETLINK_XFRM, 0, 0);
	if (err) {
		log_message(LOG_INFO, "Error while creating Kernel netlink xfrm channel");
		return -1;
	}

	if (netlink_xfrm_request(&nl, type) < 0 ||
	    netlink_parse_info(cb, &nl, ctx, false) < 0)
		err = -1;

	netlink_close(&nl);
	return err;
}

int
netlink_xfrm_lookup(void)
{
	return netlink_xfrm_dump(XFRM_MSG_GETPOLICY, netlink_xfrm_filter, NULL);
}


/*
 *	Show-layer SA / policy walkers
 */
static void
xfrm_policy_parse_tmpl(struct rtattr *attr, struct xfrm_policy *p)
{
	struct xfrm_user_tmpl *t;

	if (RTA_PAYLOAD(attr) < sizeof(*t))
		return;

	t = RTA_DATA(attr);
	p->tmpl_reqid = t->reqid;
	p->tmpl_saddr = t->saddr;
	p->tmpl_daddr = t->id.daddr;
	p->tmpl_mode = t->mode;
}

/* Key bytes are copied only when XFRM_SA_WALK_F_KEYS is set, so the default
 * render path doesn't carry sensitive material. */
static int
xfrm_sa_parse_aead(struct rtattr *attr, struct xfrm_sa *sa, uint32_t flags)
{
	struct xfrm_algo_aead *aead;
	size_t klen;

	if (RTA_PAYLOAD(attr) < sizeof(*aead))
		return -1;

	aead = RTA_DATA(attr);
	bsd_strlcpy(sa->aead_name, aead->alg_name, sizeof(sa->aead_name));
	sa->aead_key_bits = aead->alg_key_len;

	if (!(flags & XFRM_SA_WALK_F_KEYS))
		return 0;

	klen = (aead->alg_key_len + 7) / 8;
	if (klen == 0 || klen > sizeof(sa->aead_key) ||
	    klen > RTA_PAYLOAD(attr) - sizeof(*aead))
		return 0;

	memcpy(sa->aead_key, aead->alg_key, klen);
	sa->aead_key_valid = true;
	return 0;
}

static int
xfrm_sa_parse(struct nlmsghdr *n, struct xfrm_sa *sa, uint32_t flags)
{
	struct rtattr *tb[XFRMA_MAX + 1];
	struct xfrm_usersa_info *sainfo;
	struct xfrm_user_offload *xuo;
	int len = n->nlmsg_len;

	sainfo = NLMSG_DATA(n);
	len -= NLMSG_SPACE(sizeof(*sainfo));
	if (len < 0)
		return -1;

	parse_rtattr(tb, XFRMA_MAX, XFRMS_RTA(sainfo), len);

	/* Packet-offload only. */
	if (!tb[XFRMA_OFFLOAD_DEV])
		return 0;
	if (RTA_PAYLOAD(tb[XFRMA_OFFLOAD_DEV]) < sizeof(*xuo))
		return -1;
	xuo = RTA_DATA(tb[XFRMA_OFFLOAD_DEV]);
	if (!(xuo->flags & XFRM_OFFLOAD_PACKET))
		return 0;

	/* ESP only for now. */
	if (sainfo->id.proto != IPPROTO_ESP)
		return 0;

	sa->saddr = sainfo->saddr;
	sa->daddr = sainfo->id.daddr;
	sa->family = sainfo->family;
	sa->proto = sainfo->id.proto;
	sa->mode = sainfo->mode;
	sa->spi = sainfo->id.spi;
	sa->reqid = sainfo->reqid;
	sa->replay_window = sainfo->replay_window;
	sa->flags = sainfo->flags;
	sa->curlft = sainfo->curlft;
	sa->stats = sainfo->stats;
	sa->offload_ifindex = xuo->ifindex;
	sa->offload_flags = xuo->flags;

	if (tb[XFRMA_ALG_AEAD] &&
	    xfrm_sa_parse_aead(tb[XFRMA_ALG_AEAD], sa, flags) < 0)
		return -1;

	return 1;
}

static int
xfrm_policy_parse_show(struct nlmsghdr *n, struct xfrm_policy *p)
{
	struct rtattr *tb[XFRMA_MAX + 1];
	struct xfrm_userpolicy_info *xpinfo;
	struct xfrm_user_offload *xuo;
	struct xfrm_userpolicy_type *upt;
	int len = n->nlmsg_len;

	xpinfo = NLMSG_DATA(n);
	len -= NLMSG_SPACE(sizeof(*xpinfo));
	if (len < 0)
		return -1;

	parse_rtattr(tb, XFRMA_MAX, XFRMP_RTA(xpinfo), len);

	/* Packet-offload only (also drops socket-bound dirs). */
	if (!tb[XFRMA_OFFLOAD_DEV])
		return 0;
	if (RTA_PAYLOAD(tb[XFRMA_OFFLOAD_DEV]) < sizeof(*xuo))
		return -1;
	xuo = RTA_DATA(tb[XFRMA_OFFLOAD_DEV]);
	if (!(xuo->flags & XFRM_OFFLOAD_PACKET))
		return 0;

	p->family = xpinfo->sel.family;
	p->saddr = xpinfo->sel.saddr;
	p->daddr = xpinfo->sel.daddr;
	p->prefixlen_s = xpinfo->sel.prefixlen_s;
	p->prefixlen_d = xpinfo->sel.prefixlen_d;
	p->ifindex = xuo->ifindex;
	p->dir = xpinfo->dir;
	p->priority = xpinfo->priority;

	if (tb[XFRMA_TMPL])
		xfrm_policy_parse_tmpl(tb[XFRMA_TMPL], p);

	if (tb[XFRMA_POLICY_TYPE] &&
	    RTA_PAYLOAD(tb[XFRMA_POLICY_TYPE]) >= sizeof(*upt)) {
		upt = RTA_DATA(tb[XFRMA_POLICY_TYPE]);
		p->ptype = upt->type;
	}

	return 1;
}

static int
sa_walk_bridge(__attribute__((unused)) struct sockaddr_nl *snl,
	       struct nlmsghdr *nh, void *ctx)
{
	struct sa_walk_ctx *w = ctx;
	struct xfrm_sa sa = { 0 };
	int rc;

	if (nh->nlmsg_type != XFRM_MSG_NEWSA)
		return 0;

	rc = xfrm_sa_parse(nh, &sa, w->flags);
	if (rc > 0)
		rc = w->user_cb(&sa, w->user_ctx);

	return rc;
}

int
fswan_netlink_xfrm_sa_walk(xfrm_sa_walk_cb cb, void *ctx, uint32_t flags)
{
	struct sa_walk_ctx w = {
		.user_cb	= cb,
		.user_ctx	= ctx,
		.flags		= flags,
	};

	return netlink_xfrm_dump(XFRM_MSG_GETSA, sa_walk_bridge, &w);
}

static int
policy_walk_bridge(__attribute__((unused)) struct sockaddr_nl *snl,
		   struct nlmsghdr *nh, void *ctx)
{
	struct policy_walk_ctx *w = ctx;
	struct xfrm_policy p = { 0 };
	int rc;

	if (nh->nlmsg_type != XFRM_MSG_NEWPOLICY)
		return 0;

	rc = xfrm_policy_parse_show(nh, &p);
	if (rc > 0)
		rc = w->user_cb(&p, w->user_ctx);

	return rc;
}

int
fswan_netlink_xfrm_policy_walk(xfrm_policy_walk_cb cb, void *ctx)
{
	struct policy_walk_ctx w = {
		.user_cb	= cb,
		.user_ctx	= ctx,
	};

	return netlink_xfrm_dump(XFRM_MSG_GETPOLICY, policy_walk_bridge, &w);
}


/*
 *	Module init / destroy
 */
int
fswan_netlink_xfrm_init(void)
{
	int err;

	err = netlink_open(&nl_kernel, daemon_data->nl_rcvbuf_size, SOCK_NONBLOCK,
			   NETLINK_XFRM, XFRMNLGRP_POLICY, 0);
	if (err) {
		log_message(LOG_INFO, "Error while registering Kernel netlink XFRM reflector");
		return -1;
	}

	nl_kernel.thread = thread_add_read(master, kernel_netlink, &nl_kernel,
					   nl_kernel.fd, TIMER_NEVER, 0);
	return 0;
}

int
fswan_netlink_xfrm_destroy(void)
{
	netlink_close(&nl_kernel);
	return 0;
}
