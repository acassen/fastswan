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
#include "gauge.h"
#include "vty.h"
#include "vty_gauge.h"

/* Defaults */
#define GRAPH_DEFAULT_WIDTH		40
#define GRAPH_DEFAULT_HEIGHT		6
#define GRAPH_DEFAULT_LABEL_WIDTH	8

/* Y-axis label formatter */
typedef void (*graph_fmt_fn) (char *out, size_t sz, float value);

/* Per-command display options */
struct graph_opts {
	enum gauge_color_mode		color_mode;
	int				width;		/* cells horizontally, 0 = default */
	int				height;		/* braille rows vertically, 0 = default */
	int				label_width;	/* Y-axis label column, 0 = default */
	float				scale_max;	/* explicit ceiling, 0 = auto from history peak */
	graph_fmt_fn			fmt;		/* NULL = "%.1f%%" default */
	const struct gauge_history	*h;
};

/* Prototypes */
struct graph_opts *graph_opts_alloc(void);
void vty_graph_emit(struct vty *vty, const char *title, float current,
		    const struct graph_opts *opts);
void vty_graph(struct vty *vty, const char *title, float current,
	       const struct graph_opts *opts);
