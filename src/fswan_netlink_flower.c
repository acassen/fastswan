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
#include <errno.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <linux/gen_stats.h>
#include <linux/if_ether.h>
#include <linux/tc_act/tc_pedit.h>
#include <linux/tc_act/tc_mirred.h>

/* local includes */
#include "logger.h"
#include "inet_utils.h"
#include "fswan_data.h"
#include "fswan_netlink.h"
#include "fswan_netlink_flower.h"


/* Local data */
static struct nl_handle nl_flower = { .fd = -1 };

/* Extern data */
extern struct data *daemon_data;

/* Buffer sizes */
#define FLOWER_REQ_BUFSIZE	2048
#define FLOWER_REPLY_BUFSIZE	8192

/* Bounded in-flight window for pipelined filter installs. Each pending
 * ACK is around 52 bytes on the wire, so 256 entries fit well within the
 * default netlink rcvbuf.
 */
#define FLOWER_PIPELINE_MAX	256


/*
 *	Type declarations
 */
struct flower_stats_ctx {
	uint64_t	pkts;
	uint64_t	bytes;
	bool		found;
};

struct flower_dump_ctx {
	fswan_flower_dump_cb	cb;
	void			*ctx;
};

struct flower_pending {
	uint32_t			seq;
	fswan_flower_install_cb		cb;
	void				*ctx;
};


/*
 *	Pipelined-install state. Static FIFO since kernel ACK ordering on a
 *	single socket guarantees the head's seq is always the next ACK we
 *	receive.
 */
static struct flower_pending pipeline[FLOWER_PIPELINE_MAX];
static int pipeline_n;


/*
 *	NLA nest helpers (mirror of iproute2 addattr_nest / addattr_nest_end)
 */
static struct rtattr *
addattr_nest(struct nlmsghdr *n, size_t maxlen, unsigned short type)
{
	struct rtattr *nest = NLMSG_TAIL(n);

	addattr_l(n, maxlen, type, NULL, 0);
	return nest;
}

static void
addattr_nest_end(struct nlmsghdr *n, struct rtattr *nest)
{
	nest->rta_len = (char *) NLMSG_TAIL(n) - (char *) nest;
}


/*
 *	Synchronous send / receive
 */
static int
flower_send(struct nlmsghdr *n)
{
	struct sockaddr_nl snl = { .nl_family = AF_NETLINK };

	n->nlmsg_seq = ++nl_flower.seq;
	n->nlmsg_pid = 0;

	if (sendto(nl_flower.fd, n, n->nlmsg_len, 0,
		   (struct sockaddr *) &snl, sizeof(snl)) < 0)
		return -errno;
	return 0;
}

static int
flower_recv(void (*cb)(struct nlmsghdr *, void *), void *ctx)
{
	char buf[FLOWER_REPLY_BUFSIZE]
		__attribute__((aligned(__alignof__(struct nlmsghdr))));
	struct sockaddr_nl snl;
	struct iovec iov;
	struct msghdr msg;
	struct nlmsghdr *h;
	ssize_t len;
	size_t mlen;

	while (true) {
		iov.iov_base = buf;
		iov.iov_len = sizeof(buf);
		memset(&msg, 0, sizeof(msg));
		msg.msg_name = &snl;
		msg.msg_namelen = sizeof(snl);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;

		do {
			len = recvmsg(nl_flower.fd, &msg, 0);
		} while (len < 0 && errno == EINTR);
		if (len < 0)
			return -errno;
		if (len == 0)
			return -1;

		mlen = (size_t) len;
		for (h = (struct nlmsghdr *) buf; NLMSG_OK(h, mlen);
		     h = NLMSG_NEXT(h, mlen)) {
			if (h->nlmsg_type == NLMSG_DONE)
				return 0;

			if (h->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err = NLMSG_DATA(h);

				return err->error;
			}

			if (cb)
				cb(h, ctx);

			/* Non-MULTI single-shot reply ends the conversation. */
			if (!(h->nlmsg_flags & NLM_F_MULTI))
				return 0;
		}
	}
}


/*
 *	pedit "decrement IPv4 TTL" extended action
 */
static void
addattr_pedit_ttl_dec(struct nlmsghdr *n, size_t maxlen)
{
	struct {
		struct tc_pedit_sel	sel;
		struct tc_pedit_key	keys[1];
	} parms = {
		.sel.action	= TC_ACT_PIPE,
		.sel.nkeys	= 1,
		.keys[0].val	= htonl(0xff000000),
		.keys[0].mask	= htonl(0x00ffffff),
		.keys[0].off	= 8,
	};
	struct rtattr *kex_nest, *key_nest;
	__u16 htype = TCA_PEDIT_KEY_EX_HDR_TYPE_IP4;
	__u16 cmd = TCA_PEDIT_KEY_EX_CMD_ADD;

	addattr_l(n, maxlen, TCA_PEDIT_PARMS_EX, &parms, sizeof(parms));

	kex_nest = addattr_nest(n, maxlen, TCA_PEDIT_KEYS_EX | NLA_F_NESTED);
	key_nest = addattr_nest(n, maxlen, TCA_PEDIT_KEY_EX | NLA_F_NESTED);
	addattr_l(n, maxlen, TCA_PEDIT_KEY_EX_HTYPE, &htype, sizeof(htype));
	addattr_l(n, maxlen, TCA_PEDIT_KEY_EX_CMD, &cmd, sizeof(cmd));
	addattr_nest_end(n, key_nest);
	addattr_nest_end(n, kex_nest);
}


/*
 *	mirred "egress redirect to dev <ifindex>" action
 */
static void
addattr_mirred_redirect(struct nlmsghdr *n, size_t maxlen, int redirect_ifindex)
{
	struct tc_mirred parms = {
		.action		= TC_ACT_STOLEN,
		.eaction	= TCA_EGRESS_REDIR,
		.ifindex	= redirect_ifindex,
	};

	addattr_l(n, maxlen, TCA_MIRRED_PARMS, &parms, sizeof(parms));
}


/*
 *	Wrap a single action under the parent action-list nest with its prio
 *	slot. Each action is { TCA_ACT_KIND, TCA_ACT_OPTIONS{ kind-specific } }.
 */
static struct rtattr *
flower_action_open(struct nlmsghdr *n, size_t maxlen, int prio,
		   const char *kind)
{
	struct rtattr *act_nest;

	act_nest = addattr_nest(n, maxlen, prio | NLA_F_NESTED);
	addattr_l(n, maxlen, TCA_ACT_KIND, kind, strlen(kind) + 1);
	return act_nest;
}

static void
addattr_action_pedit_ttl(struct nlmsghdr *n, size_t maxlen, int prio)
{
	struct rtattr *act_nest, *opts_nest;

	act_nest = flower_action_open(n, maxlen, prio, "pedit");
	opts_nest = addattr_nest(n, maxlen, TCA_ACT_OPTIONS | NLA_F_NESTED);
	addattr_pedit_ttl_dec(n, maxlen);
	addattr_nest_end(n, opts_nest);
	addattr_nest_end(n, act_nest);
}

static void
addattr_action_mirred(struct nlmsghdr *n, size_t maxlen, int prio,
		      int redirect_ifindex)
{
	struct rtattr *act_nest, *opts_nest;

	act_nest = flower_action_open(n, maxlen, prio, "mirred");
	opts_nest = addattr_nest(n, maxlen, TCA_ACT_OPTIONS | NLA_F_NESTED);
	addattr_mirred_redirect(n, maxlen, redirect_ifindex);
	addattr_nest_end(n, opts_nest);
	addattr_nest_end(n, act_nest);
}


/*
 *	IPv4 + optional VLAN flower match keys
 */
static void
addattr_flower_keys(struct nlmsghdr *n, size_t maxlen,
		    const struct fswan_flower_sel *sel, uint16_t vlan_id)
{
	__be16 eth_type_ip = htons(ETH_P_IP);
	__be16 eth_type_vlan = htons(ETH_P_8021Q);
	__be32 saddr_mask = inet_bits_to_mask(sel->prefixlen_s);
	__be32 daddr_mask = inet_bits_to_mask(sel->prefixlen_d);

	if (vlan_id) {
		addattr_l(n, maxlen, TCA_FLOWER_KEY_ETH_TYPE,
			  &eth_type_vlan, sizeof(eth_type_vlan));
		addattr_l(n, maxlen, TCA_FLOWER_KEY_VLAN_ID,
			  &vlan_id, sizeof(vlan_id));
		addattr_l(n, maxlen, TCA_FLOWER_KEY_VLAN_ETH_TYPE,
			  &eth_type_ip, sizeof(eth_type_ip));
	} else {
		addattr_l(n, maxlen, TCA_FLOWER_KEY_ETH_TYPE,
			  &eth_type_ip, sizeof(eth_type_ip));
	}
	addattr_l(n, maxlen, TCA_FLOWER_KEY_IPV4_SRC,
		  &sel->saddr, sizeof(sel->saddr));
	addattr_l(n, maxlen, TCA_FLOWER_KEY_IPV4_SRC_MASK,
		  &saddr_mask, sizeof(saddr_mask));
	addattr_l(n, maxlen, TCA_FLOWER_KEY_IPV4_DST,
		  &sel->daddr, sizeof(sel->daddr));
	addattr_l(n, maxlen, TCA_FLOWER_KEY_IPV4_DST_MASK,
		  &daddr_mask, sizeof(daddr_mask));
}


/*
 *	clsact qdisc add / del. Both messages share the (TC_H_CLSACT, 0)
 *	handle and the TC_H_CLSACT parent classid.
 */
int
fswan_netlink_flower_clsact(int ifindex, bool add)
{
	struct {
		struct nlmsghdr	nlh;
		struct tcmsg	t;
		char		buf[64];
	} req = {
		.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(req.t)),
		.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
		.nlh.nlmsg_type = add ? RTM_NEWQDISC : RTM_DELQDISC,
		.t.tcm_family = AF_UNSPEC,
		.t.tcm_ifindex = ifindex,
		.t.tcm_parent = TC_H_CLSACT,
		.t.tcm_handle = TC_H_MAKE(TC_H_CLSACT, 0),
	};
	const char *kind = "clsact";
	int err;

	if (add)
		req.nlh.nlmsg_flags |= NLM_F_EXCL | NLM_F_CREATE;

	if (pipeline_n)
		fswan_netlink_flower_filter_drain();

	addattr_l(&req.nlh, sizeof(req), TCA_KIND, kind, strlen(kind) + 1);

	err = flower_send(&req.nlh);
	if (err < 0)
		return err;
	return flower_recv(NULL, NULL);
}


/*
 *	RTM_NEWTFILTER builder shared by the sync and pipelined paths.
 *	Sends without waiting for the ACK. Caller decides whether to
 *	consume one ACK (sync) or queue the seq for later batched drain
 *	(pipelined).
 */
static int
flower_filter_send_msg(int ifindex, uint32_t handle,
		       const struct fswan_flower_sel *sel,
		       uint16_t vlan_id, int redirect_ifindex,
		       uint32_t *seq_out)
{
	__be16 protocol = htons(vlan_id ? ETH_P_8021Q : ETH_P_IP);
	__u32 cls_flags = TCA_CLS_FLAGS_SKIP_SW;
	struct {
		struct nlmsghdr	nlh;
		struct tcmsg	t;
		char		buf[FLOWER_REQ_BUFSIZE];
	} req = {
		.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(req.t)),
		.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
				   NLM_F_EXCL | NLM_F_CREATE,
		.nlh.nlmsg_type = RTM_NEWTFILTER,
		.t.tcm_family = AF_UNSPEC,
		.t.tcm_ifindex = ifindex,
		.t.tcm_parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS),
		.t.tcm_info = TC_H_MAKE(FSWAN_FLOWER_PRIO << 16, protocol),
		.t.tcm_handle = handle,
	};
	struct rtattr *opts_nest, *act_nest;
	const char *kind = "flower";
	int err;

	addattr_l(&req.nlh, sizeof(req), TCA_KIND, kind, strlen(kind) + 1);

	opts_nest = addattr_nest(&req.nlh, sizeof(req),
				 TCA_OPTIONS | NLA_F_NESTED);
	addattr_flower_keys(&req.nlh, sizeof(req), sel, vlan_id);
	addattr_l(&req.nlh, sizeof(req), TCA_FLOWER_FLAGS,
		  &cls_flags, sizeof(cls_flags));

	act_nest = addattr_nest(&req.nlh, sizeof(req),
				TCA_FLOWER_ACT | NLA_F_NESTED);
	addattr_action_pedit_ttl(&req.nlh, sizeof(req), 1);
	addattr_action_mirred(&req.nlh, sizeof(req), 2, redirect_ifindex);
	addattr_nest_end(&req.nlh, act_nest);

	addattr_nest_end(&req.nlh, opts_nest);

	err = flower_send(&req.nlh);
	if (err < 0)
		return err;
	if (seq_out)
		*seq_out = req.nlh.nlmsg_seq;
	return 0;
}

int
fswan_netlink_flower_filter_add(int ifindex, uint32_t handle,
				const struct fswan_flower_sel *sel,
				uint16_t vlan_id, int redirect_ifindex)
{
	int err;

	/* Sync paths cannot share the recv channel with in-flight
	 * pipelined ACKs without disturbing FIFO order, we need
	 * flush first. */
	if (pipeline_n)
		fswan_netlink_flower_filter_drain();

	err = flower_filter_send_msg(ifindex, handle, sel, vlan_id,
				     redirect_ifindex, NULL);
	if (err < 0)
		return err;
	return flower_recv(NULL, NULL);
}

int
fswan_netlink_flower_filter_add_pipelined(int ifindex, uint32_t handle,
					  const struct fswan_flower_sel *sel,
					  uint16_t vlan_id,
					  int redirect_ifindex,
					  fswan_flower_install_cb cb,
					  void *ctx)
{
	uint32_t seq;
	int err;

	/* Window is full so drain it before queueing more */
	if (pipeline_n == FLOWER_PIPELINE_MAX) {
		err = fswan_netlink_flower_filter_drain();
		if (err)
			return err;
	}

	err = flower_filter_send_msg(ifindex, handle, sel, vlan_id,
				     redirect_ifindex, &seq);
	if (err < 0)
		return err;

	pipeline[pipeline_n].seq = seq;
	pipeline[pipeline_n].cb = cb;
	pipeline[pipeline_n].ctx = ctx;
	pipeline_n++;
	return 0;
}

/*
 *	Fire every pending cb with err and clear the pipeline. Used to
 *	unwind cleanly when the kernel ACK stream is unrecoverable: each
 *	caller's cb owns the per-add allocations and must run to free
 *	them, otherwise we'd leak (and a later sync drain would dereference
 *	already-freed callsite state).
 */
static void
flower_pipeline_abort(int err)
{
	int i;

	for (i = 0; i < pipeline_n; i++) {
		if (pipeline[i].cb)
			pipeline[i].cb(err, pipeline[i].ctx);
	}
	pipeline_n = 0;
}

/*
 *	Drain every pending pipelined-install ACK. ACKs come back in send
 *	order (single-socket netlink guarantee), so we only ever pop the
 *	head. On socket error or seq mismatch we abort the entire pipeline
 *	with -EIO rather than block forever waiting for an ACK that will
 *	never arrive.
 */
int
fswan_netlink_flower_filter_drain(void)
{
	char buf[FLOWER_REPLY_BUFSIZE]
		__attribute__((aligned(__alignof__(struct nlmsghdr))));
	struct sockaddr_nl snl;
	struct iovec iov;
	struct msghdr msg;
	struct nlmsghdr *h;
	struct nlmsgerr *err;
	struct flower_pending *p;
	ssize_t len;
	size_t mlen;

	while (pipeline_n > 0) {
		iov.iov_base = buf;
		iov.iov_len = sizeof(buf);
		memset(&msg, 0, sizeof(msg));
		msg.msg_name = &snl;
		msg.msg_namelen = sizeof(snl);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;

		do {
			len = recvmsg(nl_flower.fd, &msg, 0);
		} while (len < 0 && errno == EINTR);
		if (len <= 0) {
			log_message(LOG_INFO, "%s(): recvmsg failed,"
					      " aborting %d pending installs"
					      " (errno=%d %s)"
					    , __FUNCTION__, pipeline_n
					    , errno, strerror(errno));
			flower_pipeline_abort(-EIO);
			return -1;
		}

		mlen = (size_t) len;
		for (h = (struct nlmsghdr *) buf; NLMSG_OK(h, mlen);
		     h = NLMSG_NEXT(h, mlen)) {
			if (h->nlmsg_type != NLMSG_ERROR)
				continue;
			if (pipeline_n == 0)
				break;

			p = &pipeline[0];
			if (h->nlmsg_seq != p->seq) {
				log_message(LOG_INFO, "%s(): unexpected ack"
						      " seq %u (expected %u),"
						      " aborting %d pending"
						    , __FUNCTION__
						    , h->nlmsg_seq, p->seq
						    , pipeline_n);
				flower_pipeline_abort(-EIO);
				return -1;
			}

			err = NLMSG_DATA(h);
			if (p->cb)
				p->cb(err->error, p->ctx);

			memmove(&pipeline[0], &pipeline[1],
				(pipeline_n - 1) * sizeof(*pipeline));
			pipeline_n--;
		}
	}
	return 0;
}


/*
 *	RTM_DELTFILTER. Identifies the rule by (parent, prio, handle).
 *	Protocol field is left zero so the kernel matches any protocol within
 *	the prio.
 */
int
fswan_netlink_flower_filter_del(int ifindex, uint32_t handle)
{
	struct {
		struct nlmsghdr	nlh;
		struct tcmsg	t;
		char		buf[64];
	} req = {
		.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(req.t)),
		.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
		.nlh.nlmsg_type = RTM_DELTFILTER,
		.t.tcm_family = AF_UNSPEC,
		.t.tcm_ifindex = ifindex,
		.t.tcm_parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS),
		.t.tcm_info = TC_H_MAKE(FSWAN_FLOWER_PRIO << 16, 0),
		.t.tcm_handle = handle,
	};
	const char *kind = "flower";
	int err;

	if (pipeline_n)
		fswan_netlink_flower_filter_drain();

	addattr_l(&req.nlh, sizeof(req), TCA_KIND, kind, strlen(kind) + 1);

	err = flower_send(&req.nlh);
	if (err < 0)
		return err;
	return flower_recv(NULL, NULL);
}


/*
 *	GETTFILTER reply parser. Reads TCA_STATS2 / TCA_STATS_BASIC for the
 *	one filter the kernel just dumped to us. TCA_STATS_BASIC accumulates
 *	SW + HW counts. For skip_sw rule the SW share is zero, so the reported
 *	value is the HW counter. TCA_STATS_PKT64 (when present) provides the
 *	high 32 bits of the packet count.
 */
static void
parse_tca_stats_basic(struct rtattr *stats2, struct flower_stats_ctx *ctx)
{
	struct rtattr *tb[TCA_STATS_MAX + 1];
	struct gnet_stats_basic *bs;

	parse_rtattr(tb, TCA_STATS_MAX, RTA_DATA(stats2), RTA_PAYLOAD(stats2));

	if (!tb[TCA_STATS_BASIC] ||
	    RTA_PAYLOAD(tb[TCA_STATS_BASIC]) < sizeof(*bs))
		return;

	bs = RTA_DATA(tb[TCA_STATS_BASIC]);
	ctx->bytes = bs->bytes;
	ctx->pkts = bs->packets;

	if (tb[TCA_STATS_PKT64] &&
	    RTA_PAYLOAD(tb[TCA_STATS_PKT64]) == sizeof(uint64_t))
		ctx->pkts = *(uint64_t *) RTA_DATA(tb[TCA_STATS_PKT64]);

	ctx->found = true;
}

static void
flower_stats_cb(struct nlmsghdr *h, void *arg)
{
	struct flower_stats_ctx *ctx = arg;
	struct tcmsg *t = NLMSG_DATA(h);
	struct rtattr *tb[TCA_MAX + 1];
	int len = h->nlmsg_len - NLMSG_LENGTH(sizeof(*t));

	if (h->nlmsg_type != RTM_NEWTFILTER || len < 0)
		return;

	parse_rtattr(tb, TCA_MAX, TCA_RTA(t), len);
	if (!tb[TCA_STATS2])
		return;

	parse_tca_stats_basic(tb[TCA_STATS2], ctx);
}

int
fswan_netlink_flower_filter_stats(int ifindex, uint32_t handle,
				  uint64_t *pkts, uint64_t *bytes)
{
	struct {
		struct nlmsghdr	nlh;
		struct tcmsg	t;
		char		buf[64];
	} req = {
		.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(req.t)),
		.nlh.nlmsg_flags = NLM_F_REQUEST,
		.nlh.nlmsg_type = RTM_GETTFILTER,
		.t.tcm_family = AF_UNSPEC,
		.t.tcm_ifindex = ifindex,
		.t.tcm_parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS),
		.t.tcm_info = TC_H_MAKE(FSWAN_FLOWER_PRIO << 16, 0),
		.t.tcm_handle = handle,
	};
	const char *kind = "flower";
	struct flower_stats_ctx ctx = { 0 };
	int err;

	if (pipeline_n)
		fswan_netlink_flower_filter_drain();

	addattr_l(&req.nlh, sizeof(req), TCA_KIND, kind, strlen(kind) + 1);

	err = flower_send(&req.nlh);
	if (err < 0)
		return err;

	err = flower_recv(flower_stats_cb, &ctx);
	if (err < 0 || !ctx.found)
		return err < 0 ? err : -1;

	*pkts = ctx.pkts;
	*bytes = ctx.bytes;
	return 0;
}


/*
 *	RTM_GETTFILTER NLM_F_DUMP. One round-trip yields every filter under
 *	(clsact ingress, FSWAN_FLOWER_PRIO) on the iface. per-message
 *	callback fires once per filter with its handle and HW counter. Used
 *	by the show layer to amortize per-policy stats reads (one syscall
 *	per iface instead of one per policy).
 */
static void
flower_dump_msg_cb(struct nlmsghdr *h, void *arg)
{
	struct flower_dump_ctx *d = arg;
	struct tcmsg *t = NLMSG_DATA(h);
	struct rtattr *tb[TCA_MAX + 1];
	struct flower_stats_ctx s = { 0 };
	int len = h->nlmsg_len - NLMSG_LENGTH(sizeof(*t));

	if (h->nlmsg_type != RTM_NEWTFILTER || len < 0)
		return;

	parse_rtattr(tb, TCA_MAX, TCA_RTA(t), len);
	if (!tb[TCA_STATS2])
		return;

	parse_tca_stats_basic(tb[TCA_STATS2], &s);
	if (s.found)
		d->cb(t->tcm_handle, s.pkts, s.bytes, d->ctx);
}

int
fswan_netlink_flower_dump(int ifindex,
			  fswan_flower_dump_cb cb, void *ctx)
{
	struct {
		struct nlmsghdr	nlh;
		struct tcmsg	t;
		char		buf[64];
	} req = {
		.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(req.t)),
		.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
		.nlh.nlmsg_type = RTM_GETTFILTER,
		.t.tcm_family = AF_UNSPEC,
		.t.tcm_ifindex = ifindex,
		.t.tcm_parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS),
		.t.tcm_info = TC_H_MAKE(FSWAN_FLOWER_PRIO << 16, 0),
	};
	const char *kind = "flower";
	struct flower_dump_ctx d = { .cb = cb, .ctx = ctx };
	int err;

	if (pipeline_n)
		fswan_netlink_flower_filter_drain();

	addattr_l(&req.nlh, sizeof(req), TCA_KIND, kind, strlen(kind) + 1);

	err = flower_send(&req.nlh);
	if (err < 0)
		return err;
	return flower_recv(flower_dump_msg_cb, &d);
}


/*
 *	Module init / destroy
 */
int
fswan_netlink_flower_init(void)
{
	int err;

	err = netlink_open(&nl_flower, daemon_data->nl_rcvbuf_size, 0,
			   NETLINK_ROUTE, 0, 0);
	if (err) {
		log_message(LOG_INFO, "Error while creating Kernel netlink"
				      " flower channel");
		return -1;
	}
	return 0;
}

int
fswan_netlink_flower_destroy(void)
{
	if (pipeline_n)
		fswan_netlink_flower_filter_drain();
	netlink_close(&nl_flower);
	return 0;
}
