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

#ifndef _MEMORY_H
#define _MEMORY_H

/* system includes */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* extern types */
extern unsigned long mem_allocated;
extern void *xalloc(unsigned long);
extern void *zalloc(unsigned long);
extern void *xcalloc(size_t, unsigned long);
extern void xfree(void *);

/* Global alloc macro */
#define ALLOC(n) (xalloc(n))

/* Local defines */
#ifdef _DEBUG_

#define MAX_ALLOC_LIST 40000

#define MALLOC(n)    ( memory_malloc((n), \
                      (__FILE__), (__FUNCTION__), (__LINE__)) )
#define FREE(b)      ( memory_free((b), \
                      (__FILE__), (__FUNCTION__), (__LINE__)) )
#define REALLOC(b,n) ( memory_realloc((b), (n), \
                      (__FILE__), (__FUNCTION__), (__LINE__)) )

/* Memory debug prototypes defs */
extern char *memory_malloc(unsigned long, char *, const char *, const int);
extern int memory_free(void *, char *, const char *, const int);
extern void *memory_realloc(void *, unsigned long, char *, const char *, const int);
extern void memory_free_final(char *);

#else

#define MALLOC(n)    (zalloc(n))
#define CALLOC(n,s)  (xcalloc((n),(s)))
#define FREE(p)      (xfree(p))
#define REALLOC(p,n) (realloc((p),(n)))

#endif

/* Common defines */
#define PMALLOC(p)	{ p = MALLOC(sizeof(*p)); }
#define FREE_PTR(p)     { if (p) { FREE(p);} }
#define FREE_CONST_PTR(p) { if (p) { FREE_CONST(p);} }

#endif
