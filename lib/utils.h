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

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/types.h>

#ifndef likely
# define likely(x) __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
# define unlikely(x) __builtin_expect(!!(x), 0)
#endif

/* Evaluates to -1, 0 or 1 as appropriate.
 * Avoids a - b <= 0 producing "warning: assuming signed overflow does not occur when simplifying ‘X - Y <= 0’ to ‘X <= Y’ [-Wstrict-overflow]" */
#define less_equal_greater_than(a,b)    ({ typeof(a) _a = (a); typeof(b) _b = (b); (_a) < (_b) ? -1 : (_a) == (_b) ? 0 : 1; })

/* always useful */
#ifndef min
# define min(A, B) ((A) > (B) ? (B) : (A))
#endif
#ifndef max
# define max(A, B) ((A) > (B) ? (A) : (B))
#endif

/* Functions that can return EAGAIN also document that they can return
 * EWOULDBLOCK, and that both should be checked. If they are the same
 * value, that is unnecessary. */
#if EAGAIN == EWOULDBLOCK
#define check_EAGAIN(xx)        ((xx) == EAGAIN)
#else
#define check_EAGAIN(xx)        ((xx) == EAGAIN || (xx) == EWOULDBLOCK)
#endif

/* Used in functions returning a string matching a defined value */
#define switch_define_str(x) case x: return #x

/* Some library functions that take pointer parameters should have them
 * specified as const pointers, but don't. We need to cast away the constness,
 * but also want to avoid compiler warnings for doing so. The following "trick"
 * achieves that. */
#define no_const(type, var_cp) \
({ union { type *p; const type *cp; } ps = { .cp = var_cp }; \
 ps.p;})
#define no_const_char_p(var_cp) no_const(char, var_cp)

/* ARRAY_SIZE */
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/* struct st { char b[13]; };
 * int aligned_size = ALIGN(sizeof (st), 8);  => 16 */
# define __ALIGN_MASK(x, mask)	(((x) + (mask)) & ~(mask))
# define ALIGN(x, a)		__ALIGN_MASK(x, (typeof(x))(a)-1)
# define PTR_ALIGN(p, a)	((typeof(p))ALIGN((size_t)(p), (a)))

/* STR(MACRO) stringifies MACRO */
#define _STR(x) #x
#define STR(x) _STR(x)

/* global vars exported */
extern unsigned long debug;

/* Prototypes defs */
int scnprintf(char *buf, size_t size, const char *format, ...)
	__attribute__ ((format (printf, 3, 4)));
int vscnprintf(char *buf, size_t size, const char *format, va_list args);
size_t hexdump(const char *prefix, const unsigned char *buffer, size_t size);
ssize_t hexdump_format(const char *prefix, unsigned char *dst, size_t dsize,
		       const unsigned char *src, size_t ssize);
void buffer_to_c_array(const char *name, const unsigned char *buffer, size_t blen);
char *get_local_name(void);
int string_equal(const char *str1, const char *str2);
char hextochar(char c);
int hextostring(char *data, int size, char *buffer_out);
int stringtohex(const char *buffer_in, int size_in, char *buffer_out, int size_out);
int swapbuffer(uint8_t *buffer_in, int size_in, uint8_t *buffer_out);
uint32_t adler_crc32(uint8_t *data, size_t len);
uint32_t fletcher_crc32(uint8_t *data, size_t len);
int integer_to_string(const int value, char *str, size_t size);
uint32_t poor_prng(unsigned int *seed);
uint64_t xorshift_prng(uint64_t *state);
size_t bsd_strlcpy(char *dst, const char *src, size_t dsize);
size_t bsd_strlcat(char *dst, const char *src, size_t dsize);
char *memcpy2str(char *dst, size_t dsize, const void *src, size_t ssize);
int open_pipe(int pipe_arr[2]);
uint32_t fnv1a_hash(const uint8_t *buffer, size_t size);
void split_line(char *buf, int *argc, char **argv, const char *delim, int max_args);

static inline uint32_t
next_power_of_2(uint32_t n)
{
	n--;
	n |= n >> 1;
	n |= n >> 2;
	n |= n >> 4;
	n |= n >> 8;
	n |= n >> 16;

	return n + 1;
}
