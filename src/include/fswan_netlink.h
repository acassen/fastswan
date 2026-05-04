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
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>

#include "thread.h"

/* types definitions */
struct nl_handle {
	int			fd;
	uint32_t		nl_pid;
	__u32			seq;
	struct thread		*thread;
};

enum xfrm_policy_flags {
	XFRM_POLICY_FL_IN_BIT,
	XFRM_POLICY_FL_OUT_BIT,
};

struct xfrm_policy {
	xfrm_address_t		daddr;
	xfrm_address_t		saddr;
	__u16			family;
	__u8			prefixlen_d;
	__u8			prefixlen_s;
	int			ifindex;

	unsigned long		flags;

	/* Show-layer template/policy fields */
	__u32			tmpl_reqid;
	xfrm_address_t		tmpl_saddr;
	xfrm_address_t		tmpl_daddr;
	__u8			tmpl_mode;
	__u8			dir;
	__u32			priority;
	__u8			ptype;
};

struct xfrm_sa {
	xfrm_address_t		saddr;
	xfrm_address_t		daddr;
	__u16			family;
	__u8			proto;		/* IPPROTO_ESP only for now */
	__u8			mode;		/* XFRM_MODE_TUNNEL/_TRANSPORT */
	__u32			spi;		/* __be32 wire format */
	__u32			reqid;
	__u32			replay_window;
	__u8			flags;		/* xfrm_usersa_info.flags */

	char			aead_name[64];
	__u32			aead_key_bits;	/* cipher key size, always populated */
	bool			aead_key_valid;	/* true when aead_key holds the bytes */
	__u8			aead_key[64];	/* embedded buffer, no allocation */

	struct xfrm_lifetime_cur curlft;
	struct xfrm_stats	stats;

	int			offload_ifindex;
	__u8			offload_flags;	/* xfrm_user_offload.flags raw */
};

enum xfrm_sa_walk_flags {
	XFRM_SA_WALK_F_KEYS = 1 << 0,	/* copy aead_key bytes into sa->aead_key */
};

typedef int (*xfrm_sa_walk_cb)(struct xfrm_sa *, void *);
typedef int (*xfrm_policy_walk_cb)(struct xfrm_policy *, void *);


/* Defines */
#define NL_DEFAULT_BUFSIZE	(64*1024)

#ifndef NLMSG_TAIL
#define NLMSG_TAIL(nmsg) ((void *)(((char *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))
#endif

#define RTA_TAIL(rta)	(struct rtattr *) (char *)(rta) + RTA_ALIGN((rta)->rta_len)

#define XFRMS_RTA(x)  ((struct rtattr*)(((char*)(x)) + NLMSG_ALIGN(sizeof(struct xfrm_usersa_info))))
#define XFRMS_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct xfrm_usersa_info))

#define XFRMP_RTA(x)  ((struct rtattr*)(((char*)(x)) + NLMSG_ALIGN(sizeof(struct xfrm_userpolicy_info))))
#define XFRMP_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct xfrm_userpoilcy_info))

#define XFRMSID_RTA(x)  ((struct rtattr*)(((char*)(x)) + NLMSG_ALIGN(sizeof(struct xfrm_usersa_id))))
#define XFRMSID_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct xfrm_usersa_id))

#define XFRMPID_RTA(x)  ((struct rtattr*)(((char*)(x)) + NLMSG_ALIGN(sizeof(struct xfrm_userpolicy_id))))
#define XFRMPID_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct xfrm_userpoilcy_id))

#define XFRMACQ_RTA(x)	((struct rtattr*)(((char*)(x)) + NLMSG_ALIGN(sizeof(struct xfrm_user_acquire))))
#define XFRMEXP_RTA(x)	((struct rtattr*)(((char*)(x)) + NLMSG_ALIGN(sizeof(struct xfrm_user_expire))))
#define XFRMPEXP_RTA(x)	((struct rtattr*)(((char*)(x)) + NLMSG_ALIGN(sizeof(struct xfrm_user_polexpire))))
#define XFRMREP_RTA(x)	((struct rtattr*)(((char*)(x)) + NLMSG_ALIGN(sizeof(struct xfrm_user_report))))

/* Internal */
int addattr_l(struct nlmsghdr *n, size_t maxlen, unsigned short type,
	      const void *data, size_t alen);
void parse_rtattr(struct rtattr **tb, int max, struct rtattr *rta, size_t len);
int netlink_open(struct nl_handle *nl, unsigned rcvbuf_size, int flags,
		 int protocol, unsigned group, ...);
void netlink_close(struct nl_handle *nl);
int netlink_parse_info(int (*filter)(struct sockaddr_nl *, struct nlmsghdr *, void *),
		       struct nl_handle *nl, void *userdata, bool read_all);
int fswan_netlink_xfrm_init(void);
int fswan_netlink_xfrm_destroy(void);

/* Prototypes */
int netlink_xfrm_lookup(void);
int fswan_netlink_xfrm_sa_walk(xfrm_sa_walk_cb cb, void *ctx, uint32_t flags);
int fswan_netlink_xfrm_policy_walk(xfrm_policy_walk_cb cb, void *ctx);
int fswan_netlink_if_lookup(int ifindex);
int fswan_netlink_neigh_lookup(uint32_t addr, int ifindex);
int fswan_netlink_route_lookup(uint32_t addr, uint32_t *gw, int *oif);
int fswan_netlink_init(void);
int fswan_netlink_destroy(void);
