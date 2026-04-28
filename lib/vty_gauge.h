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

#include "gauge.h"
#include "vty.h"

/* Color modes */
enum gauge_color_mode {
	GAUGE_COLOR_256 = 0,	/* 256-color palette steps (default) */
	GAUGE_COLOR_TRUE,	/* 24-bit true-color interpolation   */
};

/* Display styles */
enum gauge_style {
	GAUGE_ASCII = 0,	/* '#' filled, '.' empty */
	GAUGE_BLOCK,		/* solid Unicode block █, color-coded */
	GAUGE_BRAILLE,		/* braille filled bar, 8 sub-levels per cell, color-coded */
	GAUGE_THIN,		/* thin line ━, color-coded */
	GAUGE_DOT,		/* filled/empty circles ●/○, color-coded */
	GAUGE_BLOCK_GRAPH,	/* scrolling ▁▂▃▄▅▆▇█ graph, color-coded */
	GAUGE_BRAILLE_GRAPH,	/* 2×4 braille dot graph, color-coded */
};

/* Per-command display options — caller-allocated, opaque to vty. */
#define GAUGE_DEFAULT_WIDTH		40
#define GAUGE_DEFAULT_LABEL_WIDTH	10
struct gauge_opts {
	enum gauge_style		style;
	enum gauge_color_mode		color_mode;
	int				width;		/* bar width, 0 = GAUGE_DEFAULT_WIDTH */
	int				label_width;	/* label padding, 0 = GAUGE_DEFAULT_LABEL_WIDTH */
	const char			*left;		/* left delimiter, NULL = none */
	const char			*right;		/* right delimiter, NULL = none */
	const struct gauge_history	*h;		/* history for graph styles, NULL = none */
};

/* matrix_entry is defined in vty_matrix.h; forward-declare for vty_gauge_render. */
struct matrix_entry;

/* Prototypes */
const char *vty_ratio_color(float ratio, enum gauge_color_mode mode);
enum gauge_style gauge_style_parse(const char *s);
struct gauge_opts *gauge_opts_alloc(enum gauge_style style);
void vty_gauge_emit(struct vty *vty, const char *label, float ratio,
		    const struct gauge_opts *opts);
void vty_gauge(struct vty *vty, const char *label, float ratio,
	       const struct gauge_opts *opts);
