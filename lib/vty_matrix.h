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

#include "vty_gauge.h"
#include "vty.h"

#define MATRIX_LABEL_LEN    5	/* recommended label_width for gauge cells */
#define MATRIX_DEFAULT_COLS 4

/* One cell in the grid.  value is the per-cell scalar (e.g. load ratio).
 * The render callback receives the entry and the shared opts from matrix_opts. */
struct matrix_entry {
	char	label[16];
	void	(*render)(struct vty *vty, const char *label,
			  const struct matrix_entry *e, void *arg);
	float	value;
};

/* Layout + shared widget opts.  arg is passed as-is to every render call. */
struct matrix_opts {
	int	cols;	/* cells per row, 0 = MATRIX_DEFAULT_COLS */
	void	*arg;	/* shared widget opts (e.g. struct gauge_opts *) */
};

/* Prototypes */
struct matrix_opts *matrix_gauge_opts_alloc(int cols, enum gauge_style style);
void vty_matrix_gauge_render(struct vty *vty, const char *label,
			     const struct matrix_entry *e, void *arg);
void vty_matrix(struct vty *vty, const char *title,
		const struct matrix_entry *entries, int n,
		const struct matrix_opts *opts);
