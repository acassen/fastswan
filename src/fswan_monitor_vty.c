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
#include <unistd.h>
#include <sys/socket.h>
#include "command.h"
#include "vty.h"
#include "vty_gauge.h"
#include "vty_matrix.h"
#include "thread.h"
#include "timer.h"
#include "buffer.h"
#include "fswan_cpu_vty.h"

/* Extern data */
extern struct thread_master *master;

/* ANSI escape sequences */
#define MONITOR_CLEAR_SCREEN	"\033[2J\033[H"
#define MONITOR_CURSOR_HOME	"\033[H"
#define MONITOR_ERASE_TAIL	"\033[0J"

/* Private data */
struct fswan_monitor {
	struct vty	*vty;
	int		(*show) (struct vty *);
	uint64_t	timer;
	void		*opts;
};

static void
fswan_monitor_stop(struct fswan_monitor *m)
{
	struct vty *vty = m->vty;

	vty->index = NULL;
	vty_prompt_restore(vty);
	vty_read_resume(vty);
	free(m->opts);
	free(m);
}

static void
fswan_monitor_refresh(struct thread *t)
{
	struct fswan_monitor *m = THREAD_ARG(t);
	struct vty *vty = m->vty;
	unsigned char buf[64];

	/* VTY is closing */
	if (vty->status == VTY_CLOSE) {
		free(m->opts);
		free(m);
		return;
	}

	/* vty_read() re-registers itself after the command handler
	 * returns. cancel it each time to be sure.
	 */
	if (vty->t_read) {
		thread_del(vty->t_read);
		vty->t_read = NULL;
	}

	/* Any keypress stops the monitor */
	if (recv(vty->fd, buf, sizeof(buf), MSG_DONTWAIT) > 0) {
		fswan_monitor_stop(m);
		return;
	}

	vty_send_out(vty, MONITOR_CURSOR_HOME);
	vty->priv = m->opts;
	m->show(vty);
	vty->priv = NULL;
	vty_out(vty, "%s-- press any key to stop --%s", VTY_NEWLINE, VTY_NEWLINE);
	buffer_flush_all(vty->obuf, vty->fd);
	vty_send_out(vty, MONITOR_ERASE_TAIL);

	thread_add_timer(master, fswan_monitor_refresh, m, m->timer);
}

static int
fswan_monitor_start(struct vty *vty, int interval, int (*show) (struct vty *),
		    void *opts)
{
	struct fswan_monitor *m;

	if (!opts) {
		vty_out(vty, "%% out of memory%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	m = calloc(1, sizeof(*m));
	if (!m) {
		vty_out(vty, "%% out of memory%s", VTY_NEWLINE);
		free(opts);
		return CMD_WARNING;
	}

	m->vty = vty;
	m->show = show;
	m->timer = interval * TIMER_HZ;
	m->opts = opts;

	vty->index = m;
	vty_prompt_hold(vty);
	vty_send_out(vty, MONITOR_CLEAR_SCREEN);
	buffer_reset(vty->obuf);

	thread_add_event(master, fswan_monitor_refresh, m, 0);
	return CMD_SUCCESS;
}


/*
 *	VTY commands
 */
DEFUN(monitor_system_cpu,
      monitor_system_cpu_cmd,
      "monitor <1-60> system cpu",
      "Refresh display\n"
      "Refresh interval in seconds\n"
      "System information\n"
      "Per-core CPU utilization\n")
{
	int interval;

	VTY_GET_INTEGER_RANGE("interval", interval, argv[0], 1, 60);
	return fswan_monitor_start(vty, interval, fswan_cpu_vty,
				   gauge_opts_alloc(GAUGE_BRAILLE_GRAPH));
}

DEFUN(monitor_system_cpu_style,
      monitor_system_cpu_style_cmd,
      "monitor <1-60> system cpu (ascii|block|braille|thin|dot|block-graph|braille-graph)",
      "Refresh display\n"
      "Refresh interval in seconds\n"
      "System information\n"
      "Per-core CPU utilization\n"
      "ASCII bar gauge\n"
      "Solid block gauge with color\n"
      "Braille filled bar with color\n"
      "Thin line bar gauge with color\n"
      "Dot bar gauge with color\n"
      "Scrolling block graph with color\n"
      "Braille dot graph with color\n")
{
	int interval;

	VTY_GET_INTEGER_RANGE("interval", interval, argv[0], 1, 60);
	return fswan_monitor_start(vty, interval, fswan_cpu_vty,
				   gauge_opts_alloc(gauge_style_parse(argv[1])));
}

DEFUN(monitor_system_cpu_matrix,
      monitor_system_cpu_matrix_cmd,
      "monitor <1-60> system cpu matrix",
      "Refresh display\n"
      "Refresh interval in seconds\n"
      "System information\n"
      "Per-core CPU utilization\n"
      "2D grid layout\n")
{
	int interval;

	VTY_GET_INTEGER_RANGE("interval", interval, argv[0], 1, 60);
	return fswan_monitor_start(vty, interval, fswan_cpu_matrix_vty,
				   matrix_gauge_opts_alloc(3, GAUGE_BRAILLE));
}

DEFUN(monitor_system_cpu_matrix_style,
      monitor_system_cpu_matrix_style_cmd,
      "monitor <1-60> system cpu matrix (ascii|block|braille|thin|dot)",
      "Refresh display\n"
      "Refresh interval in seconds\n"
      "System information\n"
      "Per-core CPU utilization\n"
      "2D grid layout\n"
      "ASCII bar gauge\n"
      "Solid block gauge with color\n"
      "Braille filled bar with color\n"
      "Thin line bar gauge with color\n"
      "Dot bar gauge with color\n")
{
	int interval;

	VTY_GET_INTEGER_RANGE("interval", interval, argv[0], 1, 60);
	return fswan_monitor_start(vty, interval, fswan_cpu_matrix_vty,
				   matrix_gauge_opts_alloc(3, gauge_style_parse(argv[1])));
}

DEFUN(monitor_interface_rxq,
      monitor_interface_rxq_cmd,
      "monitor <1-60> interface rx-queue",
      "Refresh display\n"
      "Refresh interval in seconds\n"
      "Interface information\n"
      "RX queue\n")
{
	/* TODO */
	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
static int
cmd_ext_monitor_install(void)
{
	install_element(VIEW_NODE, &monitor_system_cpu_cmd);
	install_element(VIEW_NODE, &monitor_system_cpu_style_cmd);
	install_element(VIEW_NODE, &monitor_system_cpu_matrix_cmd);
	install_element(VIEW_NODE, &monitor_system_cpu_matrix_style_cmd);
	install_element(VIEW_NODE, &monitor_interface_rxq_cmd);
	install_element(ENABLE_NODE, &monitor_system_cpu_cmd);
	install_element(ENABLE_NODE, &monitor_system_cpu_style_cmd);
	install_element(ENABLE_NODE, &monitor_system_cpu_matrix_cmd);
	install_element(ENABLE_NODE, &monitor_system_cpu_matrix_style_cmd);
	install_element(ENABLE_NODE, &monitor_interface_rxq_cmd);
	return 0;
}

static struct cmd_ext cmd_ext_monitor = {
	.node = NULL,
	.install = cmd_ext_monitor_install,
};

static void __attribute__((constructor))
fswan_monitor_vty_init(void)
{
	cmd_ext_register(&cmd_ext_monitor);
}
