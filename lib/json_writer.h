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

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>

/* Create a new JSON stream */
struct json_writer *jsonw_new(FILE *f);

/* End output to JSON stream */
void jsonw_destroy(struct json_writer ** const self_p);

/* Cause output to have pretty whitespace */
void jsonw_pretty(struct json_writer *self, bool on);

/* Add property name */
void jsonw_name(struct json_writer *self, const char *name);

/* Add value  */
void jsonw_vprintf_enquote(struct json_writer *, const char *, va_list)
			__attribute__ ((format(printf, 2, 0)));
void jsonw_printf(struct json_writer *, const char *, ...)
		__attribute__ ((format(printf, 2, 3)));
void jsonw_string(struct json_writer *self, const char *value);
void jsonw_bool(struct json_writer *self, bool value);
void jsonw_float(struct json_writer *self, double number);
void jsonw_float_fmt(struct json_writer *self, const char *fmt, double num);
void jsonw_uint(struct json_writer *self, uint64_t number);
void jsonw_hu(struct json_writer *self, unsigned short number);
void jsonw_int(struct json_writer *self, int64_t number);
void jsonw_null(struct json_writer *self);
void jsonw_lluint(struct json_writer *self, unsigned long long int num);

/* Useful Combinations of name and value */
void jsonw_string_field(struct json_writer *self, const char *prop, const char *val);
void jsonw_string_field_fmt(struct json_writer *self, const char *prop, const char *fmt, ...);
void jsonw_bool_field(struct json_writer *self, const char *prop, bool value);
void jsonw_float_field(struct json_writer *self, const char *prop, double num);
void jsonw_uint_field(struct json_writer *self, const char *prop, uint64_t num);
void jsonw_hu_field(struct json_writer *self, const char *prop, unsigned short num);
void jsonw_int_field(struct json_writer *self, const char *prop, int64_t num);
void jsonw_null_field(struct json_writer *self, const char *prop);
void jsonw_lluint_field(struct json_writer *self, const char *prop,
			unsigned long long int num);
void jsonw_float_field_fmt(struct json_writer *self, const char *prop,
			   const char *fmt, double val);

/* Collections */
void jsonw_start_object(struct json_writer *self);
void jsonw_end_object(struct json_writer *self);

void jsonw_start_array(struct json_writer *self);
void jsonw_end_array(struct json_writer *self);

/* Override default exception handling */
typedef void (jsonw_err_handler_fn)(const char *);
