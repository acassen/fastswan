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
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>
#include <errno.h>

/* local includes */
#include "fastswan.h"

/* Local data */
static nl_handle_t nl_kernel = { .fd = -1 };	/* Kernel reflection channel */
static nl_handle_t nl_cmd = { .fd = -1 };	/* Kernel command channel */

/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;

/* Ok this is a nasty hack but PACKET OFFLOAD is not part of all distros.
 * otherwise need to maintain a uapi copy like iproute2 does */
#ifndef XFRM_OFFLOAD_PACKET
#define XFRM_OFFLOAD_PACKET	4
#endif

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


/* iproute2 utility function */
int
addattr_l(struct nlmsghdr *n, size_t maxlen, unsigned short type, const void *data, size_t alen)
{
	unsigned short len = RTA_LENGTH(alen);
	uint32_t align_len = RTA_SPACE(alen);
	struct rtattr *rta;

	if (NLMSG_ALIGN(n->nlmsg_len) + align_len > maxlen)
		return -1;

	rta = (struct rtattr *) NLMSG_TAIL(n);
	rta->rta_type = type;
	rta->rta_len = len;
	if (alen)
		memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + align_len;

	return 0;
}

static void
parse_rtattr(struct rtattr **tb, int max, struct rtattr *rta, size_t len)
{
	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));

	while (RTA_OK(rta, len)) {
		if (rta->rta_type <= max)
			tb[rta->rta_type] = rta;
		/* Note: clang issues a -Wcast-align warning for RTA_NEXT, whereas gcc does not.
		 * gcc is more clever in it's analysis, and realises that RTA_NEXT is actually
		 * forcing alignment.
		 */
		rta = RTA_NEXT(rta, len);
	}
}

/* Parse Netlink message */
static int
netlink_parse_info(int (*filter) (struct sockaddr_nl *, struct nlmsghdr *),
		   nl_handle_t *nl, struct nlmsghdr *n, bool read_all)
{
	ssize_t len;
	int ret = 0;
	int error;
	char *nlmsg_buf __attribute__((aligned(__alignof__(struct nlmsghdr)))) = NULL;
	int nlmsg_buf_size = 0;

	while (true) {
		struct iovec iov = {
			.iov_len = 0
		};
		struct sockaddr_nl snl;
		struct msghdr msg = {
			.msg_name = &snl,
			.msg_namelen = sizeof(snl),
			.msg_iov = &iov,
			.msg_iovlen = 1,
			.msg_control = NULL,
			.msg_controllen = 0,
			.msg_flags = 0
		};
		struct nlmsghdr *h;

		/* Find out how big our receive buffer needs to be */
		do {
			len = recvmsg(nl->fd, &msg, MSG_PEEK | MSG_TRUNC);
		} while (len < 0 && errno == EINTR);

		if (len < 0) {
			ret = -1;
			break;
		}

		if (len == 0)
			break;

		if (len > nlmsg_buf_size) {
			FREE_PTR(nlmsg_buf);
			nlmsg_buf = MALLOC(len);
			nlmsg_buf_size = len;
		}

		iov.iov_base = nlmsg_buf;
		iov.iov_len = nlmsg_buf_size;

		do {
			len = recvmsg(nl->fd, &msg, 0);
		} while (len < 0 && errno == EINTR);

		if (len < 0) {
			if (check_EAGAIN(errno))
				break;
			if (errno == ENOBUFS) {
				log_message(LOG_INFO, "Netlink: Receive buffer overrun on %s socket - (%m)"
						    , nl == &nl_kernel ? "monitor" : "cmd");
				log_message(LOG_INFO, "  - increase the relevant netlink_rcv_bufs global parameter and/or set force");
			} else
				log_message(LOG_INFO, "Netlink: recvmsg error on %s socket - %d (%m)"
						    , nl == &nl_kernel ? "monitor" : "cmd", errno);
			continue;
		}

		if (len == 0) {
			log_message(LOG_INFO, "Netlink: EOF");
			ret = -1;
			break;
		}

		if (msg.msg_namelen != sizeof snl) {
			log_message(LOG_INFO, "Netlink: Sender address length error: length %u"
					    , msg.msg_namelen);
			ret = -1;
			break;
		}

		/* See -Wcast-align comment above, also applies to NLMSG_NEXT */
		for (h = (struct nlmsghdr *) nlmsg_buf; NLMSG_OK(h, (size_t)len); h = NLMSG_NEXT(h, len)) {
			/* Finish off reading. */
			if (h->nlmsg_type == NLMSG_DONE) {
				FREE(nlmsg_buf);
				return ret;
			}

			/* Error handling. */
			if (h->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err = (struct nlmsgerr *) NLMSG_DATA(h);

				/*
				 * If error == 0 then this is a netlink ACK.
				 * return if not related to multipart message.
				 */
				if (err->error == 0) {
					if (!(h->nlmsg_flags & NLM_F_MULTI) && !read_all) {
						FREE(nlmsg_buf);
						return 0;
					}
					continue;
				}

				if (h->nlmsg_len < NLMSG_LENGTH(sizeof (struct nlmsgerr))) {
					log_message(LOG_INFO, "Netlink: error: message truncated");
					FREE(nlmsg_buf);
					return -1;
				}

				log_message(LOG_INFO, "Netlink: error: %s(%d), type=%s(%u), seq=%u, pid=%u"
						    , strerror(-err->error), -err->error
						    , get_nl_msg_type(err->msg.nlmsg_type)
						    , err->msg.nlmsg_type, err->msg.nlmsg_seq
						    , err->msg.nlmsg_pid);
				FREE(nlmsg_buf);
				return -1;
			}

			/* Only take care of XFRM Policy msg */
			if (h->nlmsg_type != XFRM_MSG_NEWPOLICY &&
			    h->nlmsg_type != XFRM_MSG_DELPOLICY &&
			    h->nlmsg_type !=  XFRM_MSG_UPDPOLICY&&
			    h->nlmsg_type != XFRM_MSG_POLEXPIRE &&
			    nl != &nl_cmd && h->nlmsg_pid == nl_cmd.nl_pid)
				continue;

			error = (*filter) (&snl, h);
			if (error < 0) {
				log_message(LOG_INFO, "Netlink: filter function error");
				ret = error;
			}

			if (!(h->nlmsg_flags & NLM_F_MULTI) && !read_all) {
				FREE(nlmsg_buf);
				return ret;
			}
		}

		/* After error care. */
		if (msg.msg_flags & MSG_TRUNC) {
			log_message(LOG_INFO, "Netlink: error: message truncated");
			continue;
		}

		if (len) {
			log_message(LOG_INFO, "Netlink: error: data remnant size %zd", len);
			ret = -1;
			break;
		}
	}

	if (nlmsg_buf)
		FREE(nlmsg_buf);

	return ret;
}


/* Open Netlink channel with kernel */
static int
netlink_open(nl_handle_t *nl, unsigned rcvbuf_size, int flags, int protocol, unsigned group, ...)
{
	socklen_t addr_len;
	struct sockaddr_nl snl;
	unsigned rcvbuf_sz = rcvbuf_size ? : NL_DEFAULT_BUFSIZE;
	va_list gp;
	int err = 0;

	memset(nl, 0, sizeof (*nl));

	nl->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | flags, protocol);
	if (nl->fd < 0) {
		log_message(LOG_INFO, "Netlink: Cannot open netlink socket : (%m)");
		return -1;
	}

	memset(&snl, 0, sizeof (snl));
	snl.nl_family = AF_NETLINK;

	err = bind(nl->fd, (struct sockaddr *) &snl, sizeof (snl));
	if (err) {
		log_message(LOG_INFO, "Netlink: Cannot bind netlink socket : (%m)");
		close(nl->fd);
		nl->fd = -1;
		return -1;
	}

	/* Join the requested groups */
	va_start(gp, group);
	while (group) {
		err = setsockopt(nl->fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group, sizeof(group));
		if (err)
			log_message(LOG_INFO, "Netlink: Cannot add group %u membership on netlink socket : (%m)"
					    , group);

		group = va_arg(gp, unsigned);
	}
	va_end(gp);

	addr_len = sizeof (snl);
	err = getsockname(nl->fd, (struct sockaddr *) &snl, &addr_len);
	if (err || addr_len != sizeof (snl)) {
		log_message(LOG_INFO, "Netlink: Cannot getsockname : (%m)");
		close(nl->fd);
		nl->fd = -1;
		return -1;
	}

	if (snl.nl_family != AF_NETLINK) {
		log_message(LOG_INFO, "Netlink: Wrong address family %d", snl.nl_family);
		close(nl->fd);
		nl->fd = -1;
		return -1;
	}

	/* Save the port id for checking message source later */
	nl->nl_pid = snl.nl_pid;
	nl->seq = (uint32_t)time(NULL);

	err = setsockopt(nl->fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf_sz, sizeof(rcvbuf_size));
	if (err)
		log_message(LOG_INFO, "Cannot set SO_RCVBUF IP option. errno=%d (%m)", errno);

	return err;
}

/* Close Netlink channel with kernel */
static void
netlink_close(nl_handle_t *nl)
{
	if (!nl)
		return;

	if (nl->thread) {
		thread_cancel(nl->thread);
		nl->thread = NULL;
	}

	if (nl->fd != -1)
		close(nl->fd);

	nl->fd = -1;
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
	xfrm_policy_t policy;
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

	/* Skip socket related policy */
	if (xpinfo->dir >= XFRM_POLICY_MAX)
		return 0;

	/* Only take into account IN & OUT */
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
	memset(&policy, 0, sizeof(xfrm_policy_t));
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
netlink_xfrm_filter(struct sockaddr_nl *snl, struct nlmsghdr *h)
{
	switch (h->nlmsg_type) {
#if 0
	case XFRM_MSG_NEWSA:
	case XFRM_MSG_DELSA:
	case XFRM_MSG_UPDSA:
	case XFRM_MSG_EXPIRE:
  		xfrm_state_handle(h);
		return 0;
#endif
	case XFRM_MSG_NEWPOLICY:
	case XFRM_MSG_DELPOLICY:
	case XFRM_MSG_UPDPOLICY:
	case XFRM_MSG_POLEXPIRE:
		xfrm_policy_filter(h);
		return 0;
	default:
		log_message(LOG_INFO, "Kernel is reflecting an unknown netlink nlmsg_type: %d"
				    , h->nlmsg_type);
		break;
	}
	return 0;
}


/*
 *	Kernel Netlink reflector
 */
static void
kernel_netlink(thread_ref_t thread)
{
	nl_handle_t *nl = THREAD_ARG(thread);

	if (thread->type != THREAD_READ_TIMEOUT)
		netlink_parse_info(netlink_xfrm_filter, nl, NULL, true);

	nl->thread = thread_add_read(master, kernel_netlink, nl, nl->fd, TIMER_NEVER, 0);
}


/*
 *	Netlink XFRM lookup
 */
static int
netlink_xfrm_request(nl_handle_t *nl, uint16_t type)
{
	ssize_t status;
	struct sockaddr_nl snl = { .nl_family = AF_NETLINK };
	struct {
		struct nlmsghdr nlh;
		char buf[4096];
	} req = {
		.nlh.nlmsg_len = NLMSG_HDRLEN,
		.nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
		.nlh.nlmsg_type = type,
		.nlh.nlmsg_pid = 0,
		.nlh.nlmsg_seq = ++nl->seq,
	};

	status = sendto(nl->fd, (void *) &req, sizeof (req), 0
			      , (struct sockaddr *) &snl, sizeof(snl));
	if (status < 0) {
		log_message(LOG_INFO, "Netlink: sendto() failed: %m");
		return -1;
	}

	return 0;
}

int
netlink_xfrm_lookup(void)
{
	int err = 0;

	err = netlink_open(&nl_cmd, daemon_data->nl_rcvbuf_size, SOCK_NONBLOCK, NETLINK_XFRM
				  , 0, 0);
	if (err) {
		log_message(LOG_INFO, "Error while creating Kernel netlink xfrm channel");
		return -1;
	}

	if (netlink_xfrm_request(&nl_cmd, XFRM_MSG_GETPOLICY) < 0) {
		err = -1;
		goto end;
	}
	netlink_parse_info(netlink_xfrm_filter, &nl_cmd, NULL, false);
  end:
	netlink_close(&nl_cmd);
	return err;
}


/*
 *	Netlink Interface lookup
 */
static int
netlink_if_request(nl_handle_t *nl, unsigned char family, uint16_t type)
{
	ssize_t status;
	struct sockaddr_nl snl = { .nl_family = AF_NETLINK };
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg i;
		char buf[64];
	} req = {
		.nlh.nlmsg_len = NLMSG_LENGTH(sizeof req.i),
		.nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
		.nlh.nlmsg_type = type,
		.nlh.nlmsg_pid = 0,
		.nlh.nlmsg_seq = ++nl->seq,
		.i.ifi_family = family,
	};
	__u32 filt_mask = RTEXT_FILTER_SKIP_STATS;

	addattr_l(&req.nlh, sizeof req, IFLA_EXT_MASK, &filt_mask, sizeof(uint32_t));

	status = sendto(nl->fd, (void *) &req, sizeof (req), 0
			      , (struct sockaddr *) &snl, sizeof(snl));
	if (status < 0) {
		log_message(LOG_INFO, "Netlink: sendto() failed: %m");
		return -1;
	}

	return 0;
}

static int
netlink_if_link_filter(__attribute__((unused)) struct sockaddr_nl *snl, struct nlmsghdr *h)
{
	struct ifinfomsg *ifi;
	struct rtattr *tb[IFLA_MAX + 1];
	interface_t *new;
	char *name;
	size_t len;

	ifi = NLMSG_DATA(h);

	if (h->nlmsg_type != RTM_NEWLINK)
		return 0;

	if (h->nlmsg_len < NLMSG_LENGTH(sizeof (struct ifinfomsg)))
		return -1;
	len = h->nlmsg_len - NLMSG_LENGTH(sizeof (struct ifinfomsg));

	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len);

	/* Append */
	PMALLOC(new);
	new->ifindex = ifi->ifi_index;
	name = (char *)RTA_DATA(tb[IFLA_IFNAME]);
	strlcpy(new->ifname, name, IF_NAMESIZE);
	INIT_LIST_HEAD(&new->next);

	list_add_tail(&new->next, &daemon_data->interfaces);
	return 0;
}

static int
netlink_if_lookup(void)
{
	int err = 0;

	if (!list_empty(&daemon_data->interfaces))
		return -1;

	err = netlink_open(&nl_cmd, daemon_data->nl_rcvbuf_size, SOCK_NONBLOCK, NETLINK_ROUTE
				  , 0, 0);
	if (err) {
		log_message(LOG_INFO, "Error while creating Kernel netlink command channel");
		return -1;
	}

	if (netlink_if_request(&nl_cmd, AF_PACKET, RTM_GETLINK) < 0) {
		err = -1;
		goto end;
	}

	netlink_parse_info(netlink_if_link_filter, &nl_cmd, NULL, false);
  end:
	netlink_close(&nl_cmd);
	return err;
}


/*
 *	Kernel Netlink channel init
 */
int
fswan_netlink_init(void)
{
	int err;

	/* Interface lookup */
	netlink_if_lookup();

	/* Register Kernel netlink reflector */
	err = netlink_open(&nl_kernel, daemon_data->nl_rcvbuf_size, SOCK_NONBLOCK, NETLINK_XFRM
				     , XFRMNLGRP_POLICY, 0);
#if 0
	/* Do we need SA broadcast too ??? dont think so... */
				     , XFRMNLGRP_SA, XFRMNLGRP_POLICY, 0);
#endif
	if (err) {
		log_message(LOG_INFO, "Error while registering Kernel netlink reflector channel");
		return -1;
	}

	log_message(LOG_INFO, "Registering Kernel netlink reflector");
	nl_kernel.thread = thread_add_read(master, kernel_netlink, &nl_kernel, nl_kernel.fd,
					   TIMER_NEVER, 0);
	return 0;
}

int
fswan_netlink_destroy(void)
{
	interface_t *ifi, *ifi_tmp;

	list_for_each_entry_safe(ifi, ifi_tmp, &daemon_data->interfaces, next)
		FREE(ifi);

	log_message(LOG_INFO, "Unregistering Kernel netlink reflector");
	netlink_close(&nl_kernel);
	return 0;
}
