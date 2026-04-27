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
#include "vty_matrix.h"

/*
 *	Matrix helpers
 */
struct matrix_opts *
matrix_gauge_opts_alloc(int cols, enum gauge_style style)
{
	struct matrix_opts *o;
	struct gauge_opts *g;

	o = calloc(1, sizeof(*o) + sizeof(*g));
	if (!o)
		return NULL;
	g = (struct gauge_opts *)(o + 1);

	*g = (struct gauge_opts) {
		.style = style,
		.color_mode = GAUGE_COLOR_TRUE,
		.width = 8,
		.label_width = MATRIX_LABEL_LEN,
		.left = "[", .right = "]",
	};
	*o = (struct matrix_opts) {
		.cols = cols,
		.arg = g,
	};
	return o;
}


/*
 *	VTY helpers
 */
void
vty_matrix_gauge_render(struct vty *vty, const char *label,
			const struct matrix_entry *e, void *arg)
{
	vty_gauge_emit(vty, label, e->value, arg);
}

void
vty_matrix(struct vty *vty, const char *title,
	   const struct matrix_entry *entries, int n,
	   const struct matrix_opts *opts)
{
	int cols = opts->cols ? : MATRIX_DEFAULT_COLS;
	int col, i;

	if (title)
		vty_out(vty, " %s%s%s", title, VTY_NEWLINE, VTY_NEWLINE);

	for (i = 0; i < n; i++) {
		col = i % cols;
		if (col)
			vty_out(vty, "  ");

		entries[i].render(vty, entries[i].label, &entries[i], opts->arg);

		if (col == cols - 1 || i == n - 1)
			vty_out(vty, "%s", VTY_NEWLINE);
	}
}
