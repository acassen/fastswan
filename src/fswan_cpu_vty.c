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
#include "command.h"
#include "cpu.h"
#include "vty.h"
#include "vty_gauge.h"
#include "vty_matrix.h"
#include "fswan_cpu.h"
#include "fswan_cpu_vty.h"

/* Extern data */
extern struct cpu_load *cpu_load;


/*
 *	VTY helpers
 */
static void
fswan_cpu_list_gauge(struct vty *vty, const char *list)
{
	const struct gauge_opts defaults = { .style = GAUGE_ASCII };
	struct gauge_opts *opts = vty->priv ? : (void *)&defaults;
	const struct fswan_percpu_metrics *m;
	char label[12];
	cpu_set_t set;
	int cpu;

	cpulist_to_set(list, &set);
	cpuset_for_each(cpu, set, cpu_load->nr_cpus) {
		m = fswan_percpu_metrics_get(cpu);
		if (!m)
			continue;
		snprintf(label, sizeof(label), "  cpu%-3d", cpu);
		opts->h = &m->load_history;
		vty_gauge(vty, label, cpu_load_get(cpu_load, cpu), opts);
	}
}

static int
fswan_cpu_list_collect(const char *list, struct matrix_entry *e, int max)
{
	cpu_set_t set;
	int cpu, n = 0;

	cpulist_to_set(list, &set);
	cpuset_for_each(cpu, set, cpu_load->nr_cpus) {
		if (n >= max)
			break;
		snprintf(e[n].label, sizeof(e[n].label), "cpu%-3d", cpu);
		e[n].render = vty_matrix_gauge_render;
		e[n].value  = cpu_load_get(cpu_load, cpu);
		n++;
	}
	return n;
}

static void
fswan_cpu_gauge_cb(int node, const char *cpulist, void *arg)
{
	struct vty *vty = arg;

	vty_out(vty, " NUMA node %d  [cpus: %s]%s", node, cpulist, VTY_NEWLINE);
	fswan_cpu_list_gauge(vty, cpulist);
	vty_out(vty, "%s", VTY_NEWLINE);
}

static void
fswan_cpu_matrix_cb(int node, const char *cpulist, void *arg)
{
	struct matrix_entry entries[cpu_load->nr_cpus];
	struct matrix_opts *mopts = ((struct vty *)arg)->priv;
	struct vty *vty = arg;
	int n;

	vty_out(vty, " NUMA node %d  [cpus: %s]%s", node, cpulist, VTY_NEWLINE);
	n = fswan_cpu_list_collect(cpulist, entries, cpu_load->nr_cpus);
	vty_matrix(vty, NULL, entries, n, mopts);
	vty_out(vty, "%s", VTY_NEWLINE);
}

int
fswan_cpu_vty(struct vty *vty)
{
	if (!cpu_load) {
		vty_out(vty, "%% CPU monitoring not available%s", VTY_NEWLINE);
		return -1;
	}
	cpu_foreach_numa_node(fswan_cpu_gauge_cb, vty);
	return 0;
}

int
fswan_cpu_matrix_vty(struct vty *vty)
{
	if (!cpu_load) {
		vty_out(vty, "%% CPU monitoring not available%s", VTY_NEWLINE);
		return -1;
	}
	cpu_foreach_numa_node(fswan_cpu_matrix_cb, vty);
	return 0;
}


/*
 *	VTY commands
 */
DEFUN(show_system_cpu,
      show_system_cpu_cmd,
      "show system cpu",
      SHOW_STR
      "System information\n"
      "Per-core CPU utilization\n")
{
	struct gauge_opts *go = gauge_opts_alloc(GAUGE_BRAILLE_GRAPH);
	int ret = CMD_SUCCESS;

	if (!go) {
		vty_out(vty, "%% out of memory%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty->priv = go;
	if (fswan_cpu_vty(vty) < 0)
		ret = CMD_WARNING;

	vty->priv = NULL;
	free(go);
	return ret;
}


/*
 *	VTY init
 */
static int
cmd_ext_cpu_install(void)
{
	install_element(VIEW_NODE, &show_system_cpu_cmd);
	install_element(ENABLE_NODE, &show_system_cpu_cmd);
	return 0;
}

static struct cmd_ext cmd_ext_cpu = {
	.node = NULL,
	.install = cmd_ext_cpu_install,
};

static void __attribute__((constructor))
fswan_cpu_vty_init(void)
{
	cmd_ext_register(&cmd_ext_cpu);
}
