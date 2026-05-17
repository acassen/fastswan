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
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>
#include <errno.h>

/* local includes */
#include "memory.h"
#include "logger.h"
#include "utils.h"
#include "thread.h"
#include "inet_utils.h"
#include "fswan_data.h"
#include "fswan_if.h"
#include "fswan_netlink.h"
#include "fswan_netlink_flower.h"
#include "fswan_hairpin.h"
#include "fswan_flower.h"
#include "fswan_bpf_xfrm.h"

/* Local data */
static struct nl_handle nl_kernel_route = { .fd = -1 };	/* RTNLGRP_NEIGH reflection */
static struct nl_handle nl_cmd = { .fd = -1 };		/* Kernel command channel */

/* Extern data */
extern struct data *daemon_data;
extern struct thread_master *master;

/* NDA_RTA is not exported by all distros' linux/neighbour.h. */
#ifndef NDA_RTA
#define NDA_RTA(r) \
	((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))
#endif


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

void
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
int
netlink_parse_info(int (*filter)(struct sockaddr_nl *, struct nlmsghdr *, void *),
		   struct nl_handle *nl, void *userdata, bool read_all)
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
				log_message(LOG_INFO, "Netlink: Receive buffer overrun on fd %d - (%m)"
						    , nl->fd);
				log_message(LOG_INFO, "  - increase the relevant netlink_rcv_bufs global parameter and/or set force");
			} else
				log_message(LOG_INFO, "Netlink: recvmsg error on fd %d - %d (%m)"
						    , nl->fd, errno);
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

				log_message(LOG_INFO, "Netlink: error: %s(%d), type=%u, seq=%u, pid=%u"
						    , strerror(-err->error), -err->error
						    , err->msg.nlmsg_type, err->msg.nlmsg_seq
						    , err->msg.nlmsg_pid);
				FREE(nlmsg_buf);
				return -1;
			}

			error = (*filter) (&snl, h, userdata);
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

	FREE_PTR(nlmsg_buf);
	return ret;
}


/* Open Netlink channel with kernel */
int
netlink_open(struct nl_handle *nl, unsigned rcvbuf_size, int flags, int protocol, unsigned group, ...)
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

	inet_setsockopt_rcvbuf(nl->fd, rcvbuf_sz);

	return 0;
}

/* Close Netlink channel with kernel */
void
netlink_close(struct nl_handle *nl)
{
	if (!nl)
		return;

	if (nl->thread) {
		thread_del(nl->thread);
		nl->thread = NULL;
	}

	if (nl->fd != -1)
		close(nl->fd);

	nl->fd = -1;
}


/*
 *	Netlink interface lookup
 */
static int
netlink_if_request(struct nl_handle *nl, unsigned char family, uint16_t type, int ifindex)
{
	struct sockaddr_nl snl = { .nl_family = AF_NETLINK };
	struct {
		struct nlmsghdr	nlh;
		struct ifinfomsg i;
		char		buf[64];
	} req = {
		.nlh.nlmsg_len = NLMSG_LENGTH(sizeof req.i),
		.nlh.nlmsg_flags = (ifindex ? 0 : NLM_F_DUMP) | NLM_F_REQUEST,
		.nlh.nlmsg_type = type,
		.nlh.nlmsg_seq = ++nl->seq,
		.i.ifi_family = family,
		.i.ifi_index = ifindex,
	};
	__u32 filt_mask = RTEXT_FILTER_SKIP_STATS;

	addattr_l(&req.nlh, sizeof req, IFLA_EXT_MASK, &filt_mask, sizeof filt_mask);

	if (sendto(nl->fd, &req, sizeof req, 0,
		   (struct sockaddr *) &snl, sizeof snl) < 0) {
		log_message(LOG_INFO, "Netlink: sendto() failed: %m");
		return -1;
	}
	return 0;
}

static uint16_t
netlink_if_parse_vlan_id(struct rtattr *linkinfo)
{
	struct rtattr *li[IFLA_INFO_MAX + 1];
	struct rtattr *vd[IFLA_VLAN_MAX + 1];
	const char *kind;

	parse_rtattr(li, IFLA_INFO_MAX, RTA_DATA(linkinfo), RTA_PAYLOAD(linkinfo));
	if (!li[IFLA_INFO_KIND] || !li[IFLA_INFO_DATA])
		return 0;

	kind = RTA_DATA(li[IFLA_INFO_KIND]);
	if (strcmp(kind, "vlan"))
		return 0;

	parse_rtattr(vd, IFLA_VLAN_MAX,
		     RTA_DATA(li[IFLA_INFO_DATA]),
		     RTA_PAYLOAD(li[IFLA_INFO_DATA]));
	if (!vd[IFLA_VLAN_ID] || RTA_PAYLOAD(vd[IFLA_VLAN_ID]) != sizeof(uint16_t))
		return 0;

	return *(uint16_t *) RTA_DATA(vd[IFLA_VLAN_ID]);
}

static void
netlink_if_link_master(struct interface *iface, struct rtattr **tb)
{
	struct interface *master;
	int link_ifindex;

	if (!tb[IFLA_LINK] || tb[IFLA_LINK_NETNSID] ||
	    RTA_PAYLOAD(tb[IFLA_LINK]) != sizeof(uint32_t))
		return;

	link_ifindex = *(uint32_t *) RTA_DATA(tb[IFLA_LINK]);
	if (!link_ifindex || link_ifindex == iface->ifindex)
		return;

	master = fswan_if_get_by_ifindex(link_ifindex, true);
	if (master)
		fswan_if_link(master, iface);
}

static void
netlink_if_link_l2(struct interface *iface, struct rtattr **tb)
{
	if (tb[IFLA_ADDRESS] && RTA_PAYLOAD(tb[IFLA_ADDRESS]) == ETH_ALEN)
		memcpy(iface->hw_addr, RTA_DATA(tb[IFLA_ADDRESS]), ETH_ALEN);

	if (tb[IFLA_LINKINFO])
		iface->vlan_id = netlink_if_parse_vlan_id(tb[IFLA_LINKINFO]);
}

static int
netlink_if_link_filter(__attribute__((unused)) struct sockaddr_nl *snl,
		       struct nlmsghdr *h,
		       __attribute__((unused)) void *userdata)
{
	struct ifinfomsg *ifi = NLMSG_DATA(h);
	struct rtattr *tb[IFLA_MAX + 1];
	struct interface *iface;
	size_t len;

	if (h->nlmsg_type != RTM_NEWLINK)
		return 0;
	if (h->nlmsg_len < NLMSG_LENGTH(sizeof *ifi))
		return -1;
	len = h->nlmsg_len - NLMSG_LENGTH(sizeof *ifi);

	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len);
	if (!tb[IFLA_IFNAME])
		return -1;

	iface = fswan_if_get_by_ifindex(ifi->ifi_index, false);
	if (!iface) {
		iface = fswan_if_alloc((char *) RTA_DATA(tb[IFLA_IFNAME]),
				       ifi->ifi_index);
		if (!iface)
			return -1;
	}

	netlink_if_link_l2(iface, tb);
	netlink_if_link_master(iface, tb);
	fswan_bpf_iface_topo_publish(iface);
	fswan_bpf_redirect_publish(iface);
	return 0;
}

int
fswan_netlink_if_lookup(int ifindex)
{
	if (netlink_if_request(&nl_cmd, AF_PACKET, RTM_GETLINK, ifindex) < 0 ||
	    netlink_parse_info(netlink_if_link_filter, &nl_cmd, NULL, false) < 0)
		return -1;
	return 0;
}


/*
 *	Netlink neighbour reflector
 */
static int
netlink_neigh_filter(__attribute__((unused)) struct sockaddr_nl *snl,
		     struct nlmsghdr *h,
		     __attribute__((unused)) void *userdata)
{
	struct ndmsg *r = NLMSG_DATA(h);
	struct rtattr *tb[NDA_MAX + 1];
	uint32_t addr;
	size_t len;

	if (h->nlmsg_type != RTM_NEWNEIGH && h->nlmsg_type != RTM_DELNEIGH)
		return 0;
	if (h->nlmsg_len < NLMSG_LENGTH(sizeof *r))
		return -1;
	if (r->ndm_family != AF_INET)
		return 0;

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof *r);
	parse_rtattr(tb, NDA_MAX, NDA_RTA(r), len);
	if (!tb[NDA_DST] || RTA_PAYLOAD(tb[NDA_DST]) != sizeof(uint32_t))
		return 0;

	addr = *(uint32_t *) RTA_DATA(tb[NDA_DST]);

	if (h->nlmsg_type == RTM_DELNEIGH) {
		fswan_hairpin_neigh_delete(addr);
		fswan_flower_neigh_delete(addr);
		return 0;
	}

	if (!tb[NDA_LLADDR] || RTA_PAYLOAD(tb[NDA_LLADDR]) != ETH_ALEN)
		return 0;

	fswan_hairpin_neigh_update(addr, RTA_DATA(tb[NDA_LLADDR]),
				   r->ndm_ifindex);
	fswan_flower_neigh_update(addr, RTA_DATA(tb[NDA_LLADDR]),
				  r->ndm_ifindex);
	return 0;
}

static int
netlink_neigh_request(struct nl_handle *nl, uint32_t addr, int ifindex)
{
	struct sockaddr_nl snl = { .nl_family = AF_NETLINK };
	struct {
		struct nlmsghdr	nlh;
		struct ndmsg	ndm;
		char		buf[64];
	} req = {
		.nlh.nlmsg_len = NLMSG_LENGTH(sizeof req.ndm),
		.nlh.nlmsg_flags = NLM_F_REQUEST,
		.nlh.nlmsg_type = RTM_GETNEIGH,
		.nlh.nlmsg_seq = ++nl->seq,
		.ndm.ndm_family = AF_INET,
		.ndm.ndm_ifindex = ifindex,
	};

	addattr_l(&req.nlh, sizeof req, NDA_DST, &addr, sizeof addr);

	if (sendto(nl->fd, &req, req.nlh.nlmsg_len, 0,
		   (struct sockaddr *) &snl, sizeof snl) < 0) {
		log_message(LOG_INFO, "Netlink: sendto() failed: %m");
		return -1;
	}
	return 0;
}

int
fswan_netlink_neigh_lookup(uint32_t addr, int ifindex)
{
	if (netlink_neigh_request(&nl_cmd, addr, ifindex) < 0 ||
	    netlink_parse_info(netlink_neigh_filter, &nl_cmd, NULL, false) < 0)
		return -1;
	return 0;
}


/*
 *	Netlink route lookup (synchronous)
 */
struct netlink_route_result {
	uint32_t	gw;
	int		oif;
};

static void
parse_rta_gateway(struct rtattr *rta, uint32_t *gw)
{
	if (rta && RTA_PAYLOAD(rta) == sizeof(uint32_t))
		*gw = *(uint32_t *) RTA_DATA(rta);
}

static void
parse_rta_multipath(struct rtattr *rta, struct netlink_route_result *res)
{
	struct rtnexthop *rtnh = RTA_DATA(rta);
	struct rtattr *sub_tb[RTA_MAX + 1];
	int sublen, len = RTA_PAYLOAD(rta);

	if (!RTNH_OK(rtnh, len))
		return;

	res->oif = rtnh->rtnh_ifindex;
	sublen = rtnh->rtnh_len - sizeof(*rtnh);
	if (sublen <= 0)
		return;

	parse_rtattr(sub_tb, RTA_MAX, RTNH_DATA(rtnh), sublen);
	parse_rta_gateway(sub_tb[RTA_GATEWAY], &res->gw);
}

static int
netlink_route_filter(__attribute__((unused)) struct sockaddr_nl *snl,
		     struct nlmsghdr *h, void *userdata)
{
	struct netlink_route_result *res = userdata;
	struct rtmsg *r = NLMSG_DATA(h);
	struct rtattr *tb[RTA_MAX + 1];
	size_t len;

	if (h->nlmsg_type != RTM_NEWROUTE)
		return 0;
	if (h->nlmsg_len < NLMSG_LENGTH(sizeof *r))
		return -1;
	if (r->rtm_family != AF_INET)
		return 0;

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof *r);
	parse_rtattr(tb, RTA_MAX, RTM_RTA(r), len);

	if (tb[RTA_MULTIPATH]) {
		parse_rta_multipath(tb[RTA_MULTIPATH], res);
		return 0;
	}

	if (tb[RTA_OIF] && RTA_PAYLOAD(tb[RTA_OIF]) == sizeof(int))
		res->oif = *(int *) RTA_DATA(tb[RTA_OIF]);
	parse_rta_gateway(tb[RTA_GATEWAY], &res->gw);
	return 0;
}

static int
netlink_route_request(struct nl_handle *nl, uint32_t addr)
{
	struct sockaddr_nl snl = { .nl_family = AF_NETLINK };
	struct {
		struct nlmsghdr	nlh;
		struct rtmsg	rtm;
		char		buf[64];
	} req = {
		.nlh.nlmsg_len = NLMSG_LENGTH(sizeof req.rtm),
		.nlh.nlmsg_flags = NLM_F_REQUEST,
		.nlh.nlmsg_type = RTM_GETROUTE,
		.nlh.nlmsg_seq = ++nl->seq,
		.rtm.rtm_family = AF_INET,
		.rtm.rtm_dst_len = 32,
	};

	addattr_l(&req.nlh, sizeof req, RTA_DST, &addr, sizeof addr);

	if (sendto(nl->fd, &req, req.nlh.nlmsg_len, 0,
		   (struct sockaddr *) &snl, sizeof snl) < 0) {
		log_message(LOG_INFO, "Netlink: sendto() failed: %m");
		return -1;
	}
	return 0;
}

int
fswan_netlink_route_lookup(uint32_t addr, uint32_t *gw, int *oif)
{
	struct netlink_route_result res = {};

	if (netlink_route_request(&nl_cmd, addr) < 0 ||
	    netlink_parse_info(netlink_route_filter, &nl_cmd, &res, false) < 0)
		return -1;

	*gw = res.gw;
	*oif = res.oif;
	return 0;
}


/*
 *	Route event dispatch (RTNLGRP_NEIGH + RTNLGRP_IPV4_ROUTE broadcast)
 */
static int
netlink_route_event_filter(struct sockaddr_nl *snl, struct nlmsghdr *h,
			   void *userdata)
{
	switch (h->nlmsg_type) {
	case RTM_NEWNEIGH:
	case RTM_DELNEIGH:
		return netlink_neigh_filter(snl, h, userdata);
	case RTM_NEWROUTE:
	case RTM_DELROUTE:
		fswan_hairpin_route_event();
		return 0;
	}
	return 0;
}

static void
kernel_netlink_route(struct thread *thread)
{
	struct nl_handle *nl = THREAD_ARG(thread);

	if (thread->type != THREAD_READ_TIMEOUT)
		netlink_parse_info(netlink_route_event_filter, nl, NULL, true);

	nl->thread = thread_add_read(master, kernel_netlink_route, nl, nl->fd,
				     TIMER_NEVER, 0);
}


/*
 *	Kernel Netlink channel init
 */
int
fswan_netlink_init(void)
{
	int err;

	/* Persistent NETLINK_ROUTE command channel for on-demand if-lookups. */
	err = netlink_open(&nl_cmd, daemon_data->nl_rcvbuf_size, SOCK_NONBLOCK,
			   NETLINK_ROUTE, 0, 0);
	if (err) {
		log_message(LOG_INFO, "Error while creating Kernel netlink command channel");
		return -1;
	}

	if (fswan_netlink_xfrm_init() < 0) {
		netlink_close(&nl_cmd);
		return -1;
	}

	if (fswan_netlink_flower_init() < 0) {
		fswan_netlink_xfrm_destroy();
		netlink_close(&nl_cmd);
		return -1;
	}

	/* RTNLGRP_NEIGH + RTNLGRP_IPV4_ROUTE reflector for hairpin tracking. */
	err = netlink_open(&nl_kernel_route, daemon_data->nl_rcvbuf_size, SOCK_NONBLOCK
				          , NETLINK_ROUTE, RTNLGRP_NEIGH,
				            RTNLGRP_IPV4_ROUTE, 0);
	if (err) {
		log_message(LOG_INFO, "Error while registering Kernel netlink route reflector");
		fswan_netlink_flower_destroy();
		fswan_netlink_xfrm_destroy();
		netlink_close(&nl_cmd);
		return -1;
	}

	log_message(LOG_INFO, "Registering Kernel netlink reflectors");
	nl_kernel_route.thread = thread_add_read(master, kernel_netlink_route,
						 &nl_kernel_route,
						 nl_kernel_route.fd,
						 TIMER_NEVER, 0);
	return 0;
}

int
fswan_netlink_destroy(void)
{
	log_message(LOG_INFO, "Unregistering Kernel netlink reflectors");
	netlink_close(&nl_kernel_route);
	fswan_netlink_flower_destroy();
	fswan_netlink_xfrm_destroy();
	netlink_close(&nl_cmd);
	return 0;
}
