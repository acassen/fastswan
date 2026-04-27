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

#include <stdint.h>
#include "lease_pool.h"

struct id_pool {
	uint32_t		base;		/* first ID in range */
	uint32_t		mask_bits;	/* prefix length; size = 1 << (32 - mask_bits) */
	struct lease_pool	pool;
};

/* Prototypes */
int id_pool_get(struct id_pool *p, uint32_t *id);
int id_pool_put(struct id_pool *p, uint32_t id);
struct id_pool *id_pool_alloc(uint32_t base, uint32_t mask_bits);
void id_pool_destroy(struct id_pool *p);
