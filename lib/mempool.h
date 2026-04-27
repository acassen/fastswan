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
#include "list_head.h"

#define MPOOL_DEFAULT_SIZE	8192

struct mpool
{
	struct list_head	head;
};

void *mpool_malloc(struct mpool *mp, uint32_t size);
void *mpool_zalloc(struct mpool *mp, uint32_t size);
void *mpool_realloc(struct mpool *mp, void *old_data, uint32_t size);
void *mpool_zrealloc(struct mpool *mp, void *old_data, uint32_t size);
void mpool_free(void *data);
static void mpool_xfree(void *data);
void *mpool_memdup(struct mpool *mp, const void *src, uint32_t size);
char *mpool_strdup(struct mpool *mp, const char *src);
static char *mpool_xstrdup(struct mpool *mp, const char *src);
char *mpool_asprintf(struct mpool *mp, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

static void mpool_move(struct mpool *dst, struct mpool *src);
static void mpool_init(struct mpool *mp);
void mpool_release(struct mpool *mp);
void mpool_reset(struct mpool *mp);
int mpool_prealloc(struct mpool *mp, uint32_t size);
void *mpool_new(uint32_t size, uint32_t prealloc_size);
static void mpool_delete(void *data);

#define MPOOL_INIT(name) { LIST_HEAD_INIT((name).head) }

static inline void
mpool_init(struct mpool *mp)
{
	INIT_LIST_HEAD(&mp->head);
}

static inline void
mpool_move(struct mpool *dst, struct mpool *src)
{
	list_splice_init(&src->head, &dst->head);
}

static inline void
mpool_xfree(void *data)
{
	if (data != NULL)
		mpool_free(data);
}

static inline char *
mpool_xstrdup(struct mpool *mp, const char *src)
{
	if (src != NULL)
		return mpool_strdup(mp, src);
	return NULL;
}

static inline void
mpool_delete(void *data)
{
	mpool_release(data);
}
