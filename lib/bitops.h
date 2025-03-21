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

#ifndef _BITOPS_H
#define _BITOPS_H

#include "config.h"

#include <limits.h>
#include <stdbool.h>

/* Defines */
#define BIT_PER_LONG	(CHAR_BIT * sizeof(unsigned long))
#define BIT_MASK(idx)	(1UL << ((idx) % BIT_PER_LONG))
#define BIT_WORD(idx)	((idx) / BIT_PER_LONG)

/* Helpers */
static inline void __set_bit(unsigned idx, unsigned long *bmap)
{
	*bmap |= BIT_MASK(idx);
}

static inline void __clear_bit(unsigned idx, unsigned long *bmap)
{
	*bmap &= ~BIT_MASK(idx);
}

static inline bool __test_bit(unsigned idx, const unsigned long *bmap)
{
	return !!(*bmap & BIT_MASK(idx));
}

static inline bool __test_and_set_bit(unsigned idx, unsigned long *bmap)
{
	if (__test_bit(idx, bmap))
		return true;

	__set_bit(idx, bmap);

	return false;
}

static inline bool __test_and_clear_bit(unsigned idx, unsigned long *bmap)
{
	if (!__test_bit(idx, bmap))
		return false;

	__clear_bit(idx, bmap);

	return true;
}

static inline void __set_bit_array(unsigned idx, unsigned long bmap[])
{
	bmap[BIT_WORD(idx)] |= BIT_MASK(idx);
}

static inline void __clear_bit_array(unsigned idx, unsigned long bmap[])
{
	bmap[BIT_WORD(idx)] &= ~BIT_MASK(idx);
}

static inline bool __test_bit_array(unsigned idx, const unsigned long bmap[])
{
	return !!(bmap[BIT_WORD(idx)] & BIT_MASK(idx));
}

static inline bool __test_and_set_bit_array(unsigned idx, unsigned long bmap[])
{
	if (__test_bit_array(idx, bmap))
		return true;

	__set_bit_array(idx, bmap);

	return false;
}

/* Bits */
enum global_bits {
	LOG_CONSOLE_BIT,
	NO_SYSLOG_BIT,
	DONT_FORK_BIT,
	DUMP_CONF_BIT,
	LOG_DETAIL_BIT,
	LOG_EXTRA_DETAIL_BIT,
	DONT_RESPAWN_BIT,
#ifdef _MEM_CHECK_
	MEM_CHECK_BIT,
#ifdef _MEM_ERR_DEBUG_
	MEM_ERR_DETECT_BIT,
#endif
#ifdef _MEM_CHECK_LOG_
	MEM_CHECK_LOG_BIT,
#endif
#endif
	CONFIG_TEST_BIT,
};

#endif
