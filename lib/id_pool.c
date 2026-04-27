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

#include <stdlib.h>
#include <errno.h>

#include "id_pool.h"
#include "lease_pool.h"


int
id_pool_get(struct id_pool *p, uint32_t *id)
{
	int idx;

	if (!p || !id) {
		errno = EINVAL;
		return -1;
	}

	if (lease_pool_get(&p->pool, &idx) < 0) {
		errno = ENOSPC;
		return -1;
	}

	lease_pool_mark(&p->pool, idx);
	*id = p->base + idx;
	return 0;
}

int
id_pool_put(struct id_pool *p, uint32_t id)
{
	int idx;

	if (!p || id < p->base) {
		errno = EINVAL;
		return -1;
	}

	idx = id - p->base;
	return lease_pool_release(&p->pool, idx);
}

struct id_pool *
id_pool_alloc(uint32_t base, uint32_t mask_bits)
{
	struct id_pool *new;
	uint32_t size;

	if (!mask_bits || mask_bits > 32) {
		errno = EINVAL;
		return NULL;
	}

	new = calloc(1, sizeof(*new));
	if (!new) {
		errno = ENOMEM;
		return NULL;
	}

	new->base = base;
	new->mask_bits = mask_bits;
	size = 1U << (32 - mask_bits);

	if (lease_pool_init(&new->pool, size, true) < 0) {
		errno = ENOMEM;
		free(new);
		return NULL;
	}

	return new;
}

void
id_pool_destroy(struct id_pool *p)
{
	if (!p)
		return;

	lease_pool_destroy(&p->pool);
	free(p);
}
