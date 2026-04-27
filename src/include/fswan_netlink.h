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

#include <stdint.h>
#include <linux/netlink.h>
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
};


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


/* Prototypes */
int netlink_xfrm_lookup(void);
int fswan_netlink_init(void);
int fswan_netlink_destroy(void);
