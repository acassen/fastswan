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
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <linux/types.h>
#include <linux/if_ether.h>


/* Single shared TC priority for every flower rule fastswan installs.
 * One tcf_proto in the kernel and a flow group per match-mask in mlx5 HW
 * regardless of policy count. */
#define FSWAN_FLOWER_PRIO	100


/* Selector tuple */
struct fswan_flower_sel {
	__be32			saddr;
	__be32			daddr;
	uint8_t			prefixlen_s;
	uint8_t			prefixlen_d;
};

/* Inbound (post-decrypt) install request, boxed because seven positional
 * args invite mistakes at call sites. */
struct fswan_flower_inbound_args {
	uint16_t		chain;
	uint32_t		handle;
	struct fswan_flower_sel	sel;
	uint8_t			dst_mac[ETH_ALEN];
	uint8_t			src_mac[ETH_ALEN];
	uint16_t		push_vlan_id;	/* 0 = no vlan push */
	int			redirect_ifindex;
	bool			decrement_ttl;
};


typedef void (*fswan_flower_dump_cb)(const struct fswan_flower_sel *sel,
				     uint64_t pkts, uint64_t bytes,
				     void *ctx);
typedef void (*fswan_flower_install_cb)(int err, void *ctx);


/* Prototypes */
int fswan_netlink_flower_init(void);
int fswan_netlink_flower_destroy(void);

int fswan_netlink_flower_clsact(int ifindex, bool add);
int fswan_netlink_flower_filter_add(int ifindex, uint16_t chain, uint32_t handle,
				    const struct fswan_flower_sel *sel,
				    uint16_t vlan_id, int redirect_ifindex,
				    bool decrement_ttl);
int fswan_netlink_flower_filter_del(int ifindex, uint16_t chain, uint32_t handle);
int fswan_netlink_flower_filter_stats(int ifindex, uint16_t chain, uint32_t handle,
				      uint64_t *pkts, uint64_t *bytes);
int fswan_netlink_flower_dump(int ifindex, uint16_t chain,
			      fswan_flower_dump_cb cb, void *ctx);

int fswan_netlink_flower_filter_add_pipelined(int ifindex, uint16_t chain,
					      uint32_t handle,
					      const struct fswan_flower_sel *sel,
					      uint16_t vlan_id,
					      int redirect_ifindex,
					      bool decrement_ttl,
					      fswan_flower_install_cb cb,
					      void *ctx);
int fswan_netlink_flower_filter_add_in(int ifindex,
				       const struct fswan_flower_inbound_args *a);
int fswan_netlink_flower_filter_add_in_pipelined(int ifindex,
						 const struct fswan_flower_inbound_args *a,
						 fswan_flower_install_cb cb,
						 void *ctx);
int fswan_netlink_flower_filter_drain(void);
