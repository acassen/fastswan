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
#include "bitops.h"
#include "command.h"
#include "cpu.h"
#include "process.h"
#include "vty.h"
#include "vty_gauge.h"
#include "vty_matrix.h"
#include "fswan_data.h"
#include "fswan_cpu.h"
#include "fswan_cpu_vty.h"
#include "fswan_monitor.h"

/* Extern data */
extern struct cpu_load *cpu_load;
extern struct data *daemon_data;


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
		if (!fswan_cpu_active(cpu))
			continue;
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
		if (!fswan_cpu_active(cpu))
			continue;
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
 *	CPULIST parser shared by cpu-mask / daemon-cpu / monitor-cpu
 */
static void
cpu_all_set(cpu_set_t *set)
{
	int i, nr = cpu_nr_possible();

	CPU_ZERO(set);
	for (i = 0; i < nr; i++)
		CPU_SET(i, set);
}

static int
parse_cpulist(struct vty *vty, const char *list, cpu_set_t *set)
{
	int i, nr = cpu_nr_possible();

	cpulist_to_set(list, set);
	if (!CPU_COUNT(set)) {
		vty_out(vty, "%% Invalid CPU list '%s'%s", list, VTY_NEWLINE);
		return -1;
	}
	for (i = nr; i < CPU_SETSIZE; i++) {
		if (!CPU_ISSET(i, set))
			continue;
		vty_out(vty, "%% CPU %d out of range, system has %d CPUs%s"
			   , i, nr, VTY_NEWLINE);
		return -1;
	}
	return 0;
}

/*
 *	Effective monitor pthread set: explicit monitor-cpu, else daemon-cpu,
 *	else system default. Re-applied after any of these change.
 */
static void
apply_monitor_affinity(void)
{
	cpu_set_t set;

	if (__test_bit(FSWAN_FL_MONITOR_CPU_BIT, &daemon_data->flags))
		set = daemon_data->monitor_cpu_affinity;
	else if (__test_bit(FSWAN_FL_CPU_AFFINITY_BIT, &daemon_data->flags))
		set = daemon_data->cpu_affinity;
	else
		cpu_all_set(&set);
	fswan_monitor_set_cpu_affinity(&set);
}

DEFUN(cpu_mask,
      cpu_mask_cmd,
      "cpu-mask CPULIST",
      "Restrict daemon CPU monitoring and sampling to a subset of system CPUs\n"
      "CPU list in cpuset format, e.g. 0-3,5,7-9\n")
{
	cpu_set_t set;

	if (!cpu_load) {
		vty_out(vty, "%% CPU monitoring not available%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (parse_cpulist(vty, argv[0], &set) < 0)
		return CMD_WARNING;

	daemon_data->cpu_mask = set;
	__set_bit(FSWAN_FL_CPU_MASK_BIT, &daemon_data->flags);
	fswan_percpu_baseline_reset();
	return CMD_SUCCESS;
}

DEFUN(no_cpu_mask,
      no_cpu_mask_cmd,
      "no cpu-mask",
      NO_STR
      "Lift the CPU mask filter, every system CPU is taken into account\n")
{
	if (!__test_bit(FSWAN_FL_CPU_MASK_BIT, &daemon_data->flags)) {
		vty_out(vty, "%% CPU mask not configured%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	__clear_bit(FSWAN_FL_CPU_MASK_BIT, &daemon_data->flags);
	fswan_percpu_baseline_reset();
	return CMD_SUCCESS;
}


/*
 *	CPU affinity (pin daemon + monitor pthread)
 */
DEFUN(daemon_cpu,
      daemon_cpu_cmd,
      "daemon-cpu CPULIST",
      "Pin the daemon main thread to a CPU set, inherited by the monitor pthread "
      "unless overridden via monitor-cpu\n"
      "CPU list in cpuset format, e.g. 0-3,5,7-9\n")
{
	cpu_set_t set;

	if (parse_cpulist(vty, argv[0], &set) < 0)
		return CMD_WARNING;

	daemon_data->cpu_affinity = set;
	__set_bit(FSWAN_FL_CPU_AFFINITY_BIT, &daemon_data->flags);
	set_process_cpu_affinity(&set, "daemon");
	apply_monitor_affinity();
	return CMD_SUCCESS;
}

DEFUN(no_daemon_cpu,
      no_daemon_cpu_cmd,
      "no daemon-cpu",
      NO_STR
      "Lift daemon CPU pinning\n")
{
	cpu_set_t set;

	if (!__test_bit(FSWAN_FL_CPU_AFFINITY_BIT, &daemon_data->flags)) {
		vty_out(vty, "%% Daemon CPU affinity not configured%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	__clear_bit(FSWAN_FL_CPU_AFFINITY_BIT, &daemon_data->flags);

	cpu_all_set(&set);
	set_process_cpu_affinity(&set, "daemon");
	apply_monitor_affinity();
	return CMD_SUCCESS;
}

DEFUN(monitor_cpu,
      monitor_cpu_cmd,
      "monitor-cpu CPULIST",
      "Pin the monitor pthread to a CPU set\n"
      "CPU list in cpuset format, e.g. 0-3,5,7-9\n")
{
	cpu_set_t set;

	if (parse_cpulist(vty, argv[0], &set) < 0)
		return CMD_WARNING;

	daemon_data->monitor_cpu_affinity = set;
	__set_bit(FSWAN_FL_MONITOR_CPU_BIT, &daemon_data->flags);
	apply_monitor_affinity();
	return CMD_SUCCESS;
}

DEFUN(no_monitor_cpu,
      no_monitor_cpu_cmd,
      "no monitor-cpu",
      NO_STR
      "Lift monitor pthread CPU pinning, falling back to daemon-cpu if configured\n")
{
	if (!__test_bit(FSWAN_FL_MONITOR_CPU_BIT, &daemon_data->flags)) {
		vty_out(vty, "%% Monitor CPU affinity not configured%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	__clear_bit(FSWAN_FL_MONITOR_CPU_BIT, &daemon_data->flags);
	apply_monitor_affinity();
	return CMD_SUCCESS;
}


/*
 *	Memory locking
 */
DEFUN(lock_memory,
      lock_memory_cmd,
      "lock-memory",
      "Lock daemon pages in RAM via mlockall, preventing swap-induced "
      "latency spikes on the data path\n")
{
	if (__test_bit(FSWAN_FL_LOCK_MEMORY_BIT, &daemon_data->flags)) {
		vty_out(vty, "%% Memory already locked%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (process_lock_memory() < 0) {
		vty_out(vty, "%% Unable to lock daemon memory%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	__set_bit(FSWAN_FL_LOCK_MEMORY_BIT, &daemon_data->flags);
	return CMD_SUCCESS;
}

DEFUN(no_lock_memory,
      no_lock_memory_cmd,
      "no lock-memory",
      NO_STR
      "Unlock daemon pages\n")
{
	if (!__test_bit(FSWAN_FL_LOCK_MEMORY_BIT, &daemon_data->flags)) {
		vty_out(vty, "%% Memory not locked%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (process_unlock_memory() < 0) {
		vty_out(vty, "%% Unable to unlock daemon memory%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	__clear_bit(FSWAN_FL_LOCK_MEMORY_BIT, &daemon_data->flags);
	return CMD_SUCCESS;
}


/*
 *	Configuration writer
 */
static void
write_cpuset_line(struct vty *vty, int bit, const cpu_set_t *set, const char *keyword)
{
	char list[256];

	if (!__test_bit(bit, &daemon_data->flags))
		return;
	cpuset_to_cpulist(set, list, sizeof(list));
	vty_out(vty, "%s %s%s", keyword, list, VTY_NEWLINE);
}

static int
fswan_cpu_config_write(struct vty *vty)
{
	write_cpuset_line(vty, FSWAN_FL_CPU_MASK_BIT,
			  &daemon_data->cpu_mask, "cpu-mask");
	write_cpuset_line(vty, FSWAN_FL_CPU_AFFINITY_BIT,
			  &daemon_data->cpu_affinity, "daemon-cpu");
	write_cpuset_line(vty, FSWAN_FL_MONITOR_CPU_BIT,
			  &daemon_data->monitor_cpu_affinity, "monitor-cpu");
	if (__test_bit(FSWAN_FL_LOCK_MEMORY_BIT, &daemon_data->flags))
		vty_out(vty, "lock-memory%s", VTY_NEWLINE);
	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
static int
cmd_ext_cpu_install(void)
{
	install_element(CONFIG_NODE, &cpu_mask_cmd);
	install_element(CONFIG_NODE, &no_cpu_mask_cmd);
	install_element(CONFIG_NODE, &daemon_cpu_cmd);
	install_element(CONFIG_NODE, &no_daemon_cpu_cmd);
	install_element(CONFIG_NODE, &monitor_cpu_cmd);
	install_element(CONFIG_NODE, &no_monitor_cpu_cmd);
	install_element(CONFIG_NODE, &lock_memory_cmd);
	install_element(CONFIG_NODE, &no_lock_memory_cmd);
	install_element(VIEW_NODE, &show_system_cpu_cmd);
	install_element(ENABLE_NODE, &show_system_cpu_cmd);
	return 0;
}

static struct cmd_node fswan_cpu_node = {
	.node		= CPU_SCHED_NODE,
	.parent_node	= CONFIG_NODE,
	.config_write	= fswan_cpu_config_write,
};

static struct cmd_ext cmd_ext_cpu = {
	.node		= &fswan_cpu_node,
	.install	= cmd_ext_cpu_install,
};

static void __attribute__((constructor))
fswan_cpu_vty_init(void)
{
	cmd_ext_register(&cmd_ext_cpu);
}
