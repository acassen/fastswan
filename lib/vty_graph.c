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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vty_graph.h"

#define COLOR_RESET	"\033[0m"

/* Box drawing glyphs, UTF-8 */
#define BOX_VLINE	"\xe2\x94\x82"	/* │ U+2502 */
#define BOX_HLINE	"\xe2\x94\x80"	/* ─ U+2500 */
#define BOX_RTICK	"\xe2\x94\xa4"	/* ┤ U+2524 */
#define BOX_BTICK	"\xe2\x94\xb4"	/* ┴ U+2534 */

/* Extern vars */
extern const uint8_t braille_left[4];
extern const uint8_t braille_right[4];


/*
 *	Default formatter
 *
 * Treats value as a ratio in [0,1].
 */
static void
graph_pct_fmt(char *out, size_t sz, float value)
{
	snprintf(out, sz, "%.1f%%", value * 100.0f);
}


/*
 *	Resolve the Y-axis scale ceiling
 *
 * Explicit `scale_max` wins. Otherwise the peak across the history ring.
 * Zero history yields 0.0, which the caller turns into a no-op render.
 */
static float
graph_scale_max(const struct graph_opts *opts)
{
	const struct gauge_history *h = opts->h;
	float m = 0.0f, s;
	int i;

	if (opts->scale_max > 0.0f)
		return opts->scale_max;
	if (!h)
		return 0.0f;

	for (i = 0; i < h->count; i++) {
		s = gauge_history_get(h, i);
		if (s > m)
			m = s;
	}
	return m;
}


/*
 *	Braille mask for one cell on one row
 *
 * Thresholds are linear across the (height * 4) dot levels.
 * `line=0` is the top row, `line=height-1` is the bottom.
 * Pre-scale samples once so the inner loop is a plain compare.
 */
static uint8_t
graph_cell_mask(float ls, float rs, int line, int height)
{
	int base_rank = (height - 1 - line) * 4;
	float ls_lvl = ls * height * 4;
	float rs_lvl = rs * height * 4;
	uint8_t mask = 0;
	int row, rank;

	for (row = 0; row < 4; row++) {
		rank = base_rank + 3 - row;
		if (ls_lvl > rank)
			mask |= braille_left[row];
		if (rs_lvl > rank)
			mask |= braille_right[row];
	}
	return mask;
}


/*
 *	Emit one braille body row, history clipped to the cell window
 *
 * Row-based coloring. Every cell on the row uses the same color, derived
 * from the row's altitude (top = high ratio = red, bottom = low = green).
 * Bars naturally show a green base fading into red tips. Color is emitted
 * once at the start of the body and reset once at the end.
 */
static void
graph_emit_body(struct vty *vty, const struct gauge_history *h, int line,
		int height, int width, int pad_cells, int base,
		float scale_max, enum gauge_color_mode color_mode)
{
	int cell, body, li, ri;
	float ls, rs, lsn, rsn, row_ratio;
	uint8_t mask;
	char glyph[4];

	for (cell = 0; cell < pad_cells; cell++)
		vty_out(vty, " ");

	row_ratio = (height - line - 0.5f) / (float)height;
	vty_out(vty, "%s", vty_ratio_color(row_ratio, color_mode));

	body = width - pad_cells;
	for (cell = 0; cell < body; cell++) {
		li = base + cell * 2;
		ri = li + 1;
		ls = (li < h->count) ? gauge_history_get(h, li) : 0.0f;
		rs = (ri < h->count) ? gauge_history_get(h, ri) : 0.0f;
		lsn = ls / scale_max;
		rsn = rs / scale_max;

		mask = graph_cell_mask(lsn, rsn, line, height);
		braille_glyph(mask, glyph);
		vty_out(vty, "%s", glyph);
	}

	vty_out(vty, COLOR_RESET);
}


/* Title row, current value right-aligned to the graph edge */
static void
graph_emit_title(struct vty *vty, const char *title, const char *cur,
		 int total_width)
{
	int tlen = title ? (int)strlen(title) : 0;
	int clen = (int)strlen(cur);
	int pad = total_width - tlen - clen;

	if (pad < 1)
		pad = 1;
	vty_out(vty, "%s%*s%s%s",
		title ? title : "", pad, "", cur, VTY_NEWLINE);
}


/* X-axis baseline: "0" label + ┴ + width dashes */
static void
graph_emit_x_axis(struct vty *vty, const char *zero, int label_w, int width)
{
	int i;

	vty_out(vty, "%*s %s", label_w, zero, BOX_BTICK);
	for (i = 0; i < width; i++)
		vty_out(vty, BOX_HLINE);
}


void
vty_graph_emit(struct vty *vty, const char *title, float current,
	       const struct graph_opts *opts)
{
	int width = opts->width ? : GRAPH_DEFAULT_WIDTH;
	int height = opts->height ? : GRAPH_DEFAULT_HEIGHT;
	int label_w = opts->label_width ? : GRAPH_DEFAULT_LABEL_WIDTH;
	graph_fmt_fn fmt = opts->fmt ? : graph_pct_fmt;
	const struct gauge_history *h = opts->h;
	float scale_max;
	int needed, samples, pad_cells, base, line, total_width;
	char max_buf[32], cur_buf[32], zero_buf[32];

	if (!h)
		return;

	scale_max = graph_scale_max(opts);
	/* avoid div-by-zero, body renders all blanks when no signal */
	if (scale_max <= 0.0f)
		scale_max = 1.0f;

	fmt(max_buf, sizeof max_buf, scale_max);
	fmt(cur_buf, sizeof cur_buf, current);
	fmt(zero_buf, sizeof zero_buf, 0.0f);

	total_width = label_w + 2 + width;
	graph_emit_title(vty, title, cur_buf, total_width);

	needed = 2 * width;
	samples = h->count < needed ? h->count : needed;
	pad_cells = width - (samples + 1) / 2;
	base = h->count - samples;

	for (line = 0; line < height; line++) {
		const char *ylabel = (line == 0) ? max_buf : "";
		const char *yaxis = (line == 0) ? BOX_RTICK : BOX_VLINE;

		vty_out(vty, "%*s %s", label_w, ylabel, yaxis);
		graph_emit_body(vty, h, line, height, width, pad_cells, base,
				scale_max, opts->color_mode);
		vty_out(vty, "%s", VTY_NEWLINE);
	}

	graph_emit_x_axis(vty, zero_buf, label_w, width);
}


void
vty_graph(struct vty *vty, const char *title, float current,
	  const struct graph_opts *opts)
{
	vty_graph_emit(vty, title, current, opts);
	vty_out(vty, "%s", VTY_NEWLINE);
}


struct graph_opts *
graph_opts_alloc(void)
{
	struct graph_opts *g = calloc(1, sizeof(*g));

	if (!g)
		return NULL;
	*g = (struct graph_opts) {
		.color_mode  = GAUGE_COLOR_TRUE,
		.width       = GRAPH_DEFAULT_WIDTH,
		.height      = GRAPH_DEFAULT_HEIGHT,
		.label_width = GRAPH_DEFAULT_LABEL_WIDTH,
	};
	return g;
}
