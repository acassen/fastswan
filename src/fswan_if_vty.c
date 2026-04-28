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

/* system includes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* local includes */
#include "bitops.h"
#include "list_head.h"
#include "vty.h"
#include "command.h"
#include "ethtool.h"
#include "pci.h"
#include "fswan_data.h"
#include "fswan_if.h"
#include "fswan_if_rxq.h"
#include "fswan_bpf_prog.h"


/* Extern data */
extern struct data *daemon_data;


/*
 *	Pretty-printers
 */
static void
bw_format(uint64_t bps, char *buf, size_t len)
{
	if (bps >= 1000000000ULL)
		snprintf(buf, len, "%.2fGbps", (double)bps / 1e9);
	else if (bps >= 1000000ULL)
		snprintf(buf, len, "%.2fMbps", (double)bps / 1e6);
	else if (bps >= 1000ULL)
		snprintf(buf, len, "%.2fKbps", (double)bps / 1e3);
	else
		snprintf(buf, len, "%llubps", (unsigned long long)bps);
}

static void
pps_format(uint64_t pps, char *buf, size_t len)
{
	if (pps >= 1000000ULL)
		snprintf(buf, len, "%.2fMpps", (double)pps / 1e6);
	else if (pps >= 1000ULL)
		snprintf(buf, len, "%.2fKpps", (double)pps / 1e3);
	else
		snprintf(buf, len, "%llupps", (unsigned long long)pps);
}

static int
fswan_if_stats_show_summary(struct interface *iface, void *arg)
{
	const struct ethtool_phy_stats *s = &iface->phy_stats;
	struct vty *vty = arg;
	char rxbw[20], txbw[20], rxpps[20], txpps[20];

	bw_format(iface->rx_bw_bps, rxbw, sizeof(rxbw));
	bw_format(iface->tx_bw_bps, txbw, sizeof(txbw));
	pps_format(iface->rx_pps, rxpps, sizeof(rxpps));
	pps_format(iface->tx_pps, txpps, sizeof(txpps));
	vty_out(vty, "%-16s  %14llu  %14llu  %14llu  %14llu  %14s  %14s  %14s  %14s%s",
		iface->ifname,
		(unsigned long long)s->rx_packets,
		(unsigned long long)s->tx_packets,
		(unsigned long long)s->rx_bytes,
		(unsigned long long)s->tx_bytes,
		rxbw, txbw, rxpps, txpps, VTY_NEWLINE);
	return 0;
}

static void
fswan_if_stats_show_detail(struct vty *vty, struct interface *iface)
{
	const struct ethtool_phy_stats *p = &iface->phy_stats;
	char rxbw[20], txbw[20], rxpps[20], txpps[20];
	uint32_t q, nr;
	int *cpu_per_q;

	bw_format(iface->rx_bw_bps, rxbw, sizeof(rxbw));
	bw_format(iface->tx_bw_bps, txbw, sizeof(txbw));
	pps_format(iface->rx_pps, rxpps, sizeof(rxpps));
	pps_format(iface->tx_pps, txpps, sizeof(txpps));

	vty_out(vty, "Interface %s%s", iface->ifname, VTY_NEWLINE);
	vty_out(vty, "  PHY counters:%s", VTY_NEWLINE);
	vty_out(vty, "    %-24s %-14llu  %-24s %llu%s",
		"rx_packets:", (unsigned long long)p->rx_packets,
		"tx_packets:", (unsigned long long)p->tx_packets, VTY_NEWLINE);
	vty_out(vty, "    %-24s %-14llu  %-24s %llu%s",
		"rx_bytes:", (unsigned long long)p->rx_bytes,
		"tx_bytes:", (unsigned long long)p->tx_bytes, VTY_NEWLINE);
	vty_out(vty, "    %-24s %-14llu  %-24s %llu%s",
		"rx_discards:", (unsigned long long)p->rx_discards,
		"tx_discards:", (unsigned long long)p->tx_discards, VTY_NEWLINE);
	vty_out(vty, "    %-24s %llu%s",
		"tx_errors:", (unsigned long long)p->tx_errors, VTY_NEWLINE);
	vty_out(vty, "  Bandwidth: rx:%s  tx:%s  |  PPS: rx:%s  tx:%s%s",
		rxbw, txbw, rxpps, txpps, VTY_NEWLINE);

	if (!iface->queue_stats || !(iface->nr_rx_queues | iface->nr_tx_queues)) {
		vty_out(vty, "%s", VTY_NEWLINE);
		return;
	}

	nr = iface->nr_rx_queues > iface->nr_tx_queues ?
	     iface->nr_rx_queues : iface->nr_tx_queues;
	cpu_per_q = calloc(nr, sizeof(*cpu_per_q));
	if (!cpu_per_q) {
		vty_out(vty, "%s", VTY_NEWLINE);
		return;
	}
	memset(cpu_per_q, -1, nr * sizeof(*cpu_per_q));
	fswan_if_rxq_cpu(iface, cpu_per_q, nr);

	vty_out(vty, "  Per-queue counters:%s", VTY_NEWLINE);
	vty_out(vty, "    %3s  %4s  %14s  %14s  %12s  %14s  %14s%s",
		"q", "cpu", "rx_packets", "rx_bytes", "rx_xdp_drop",
		"tx_packets", "tx_bytes", VTY_NEWLINE);
	for (q = 0; q < nr; q++) {
		const struct ethtool_q_stats *qs = &iface->queue_stats[q];
		vty_out(vty, "    %3u  %4d  %14llu  %14llu  %12llu  %14llu  %14llu%s",
			q, cpu_per_q[q],
			(unsigned long long)qs->rx_packets,
			(unsigned long long)qs->rx_bytes,
			(unsigned long long)qs->rx_xdp_drop,
			(unsigned long long)qs->tx_packets,
			(unsigned long long)qs->tx_bytes, VTY_NEWLINE);
	}
	free(cpu_per_q);
	vty_out(vty, "%s", VTY_NEWLINE);
}

static int
fswan_if_show(struct interface *iface, void *arg)
{
	struct vty *vty = arg;

	vty_out(vty, "interface %s {%s%s }%s"
		   , iface->ifname
		   , __test_bit(FSWAN_INTERFACE_FL_SHUTDOWN_BIT, &iface->flags) ?
		     " shutdown" : ""
		   , __test_bit(FSWAN_INTERFACE_FL_RUNNING_BIT, &iface->flags) ?
		     " running" : ""
		   , VTY_NEWLINE);
	vty_out(vty, " ifindex:%d%s", iface->ifindex, VTY_NEWLINE);
	if (iface->description[0])
		vty_out(vty, " description: %s%s", iface->description, VTY_NEWLINE);
	if (iface->bpf_prog)
		vty_out(vty, " bpf-program: %s%s", iface->bpf_prog->name, VTY_NEWLINE);
	vty_out(vty, "%s", VTY_NEWLINE);
	return 0;
}


/*
 *	Commands
 */
DEFUN(interface,
      interface_cmd,
      "interface STRING",
      "Declare or enter the configuration block of a network interface;"
      " the kernel ifindex is resolved via if_nametoindex() the first time"
      " the interface is referenced and the entry is appended to"
      " local network interfaces DB.\n"
      "Kernel netdev name (e.g. eth0)\n")
{
	struct interface *iface;

	iface = fswan_if_get(argv[0], true);
	if (!iface) {
		vty_out(vty, "%% Cant resolve ifindex for '%s' (%m)%s"
			   , argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty->node = INTERFACE_NODE;
	vty->index = iface;
	return CMD_SUCCESS;
}

DEFUN(no_interface,
      no_interface_cmd,
      "no interface STRING",
      "Detach the BPF program currently attached to this interface (if any)"
      " and remove the interface declaration\n"
      "Interface name to remove\n")
{
	struct interface *iface = fswan_if_get(argv[0], false);

	if (!iface) {
		vty_out(vty, "%% Unknown interface '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	fswan_if_destroy(iface);
	return CMD_SUCCESS;
}

DEFUN(if_description,
      if_description_cmd,
      "description LINE",
      "Free-form human-readable label stored alongside the interface;"
      " purely informational, surfaced by config write\n"
      "Description text\n")
{
	struct interface *iface = vty->index;

	strlcpy(iface->description, argv[0], sizeof(iface->description) - 1);
	return CMD_SUCCESS;
}

DEFUN(if_bpf_program,
      if_bpf_program_cmd,
      "bpf-program STRING",
      "Bind a previously declared bpf-program to this interface; the kernel"
      " attach (bpf_program__attach_xdp on the netdev's ifindex) only fires"
      " when the interface is brought up via `no shutdown`\n"
      "Name of a declared bpf-program\n")
{
	struct interface *iface = vty->index;
	struct fswan_bpf_prog *p;

	p = fswan_bpf_prog_get(argv[0]);
	if (!p) {
		vty_out(vty, "%% Unknown bpf-program '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Replacing an earlier bind: detach first. */
	if (iface->bpf_prog && iface->bpf_prog != p) {
		fswan_bpf_prog_detach(iface->bpf_prog, iface);
		list_head_del(&iface->bpf_prog_list);
		iface->bpf_prog = NULL;
	}

	if (!iface->bpf_prog) {
		iface->bpf_prog = p;
		list_add_tail(&iface->bpf_prog_list, &p->iface_bind_list);
	}

	return CMD_SUCCESS;
}

DEFUN(no_if_bpf_program,
      no_if_bpf_program_cmd,
      "no bpf-program",
      "Detach and unbind whatever bpf-program is currently attached to this"
      " interface\n")
{
	struct interface *iface = vty->index;

	if (!iface->bpf_prog)
		return CMD_SUCCESS;

	fswan_bpf_prog_detach(iface->bpf_prog, iface);
	list_head_del(&iface->bpf_prog_list);
	iface->bpf_prog = NULL;
	return CMD_SUCCESS;
}

DEFUN(if_shutdown,
      if_shutdown_cmd,
      "shutdown",
      "Detach the XDP link of the bound bpf-program from this interface;"
      " keeps the binding so a later `no shutdown` re-attaches the same prog\n")
{
	struct interface *iface = vty->index;

	if (iface->bpf_prog)
		fswan_bpf_prog_detach(iface->bpf_prog, iface);
	__set_bit(FSWAN_INTERFACE_FL_SHUTDOWN_BIT, &iface->flags);
	return CMD_SUCCESS;
}

DEFUN(if_no_shutdown,
      if_no_shutdown_cmd,
      "no shutdown",
      "Bring the interface up by attaching the bound bpf-program in XDP"
      " driver mode; lazy-loads the BPF object if it isn't running yet and"
      " seeds an xfrm_offload_stats slot for this ifindex\n")
{
	struct interface *iface = vty->index;

	if (!iface->bpf_prog) {
		vty_out(vty, "%% No bpf-program bound to %s; configure"
			     " `bpf-program NAME` first%s"
			   , iface->ifname, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (fswan_bpf_prog_attach(iface->bpf_prog, iface)) {
		vty_out(vty, "%% Failed to attach bpf-program '%s' to %s%s"
			   , iface->bpf_prog->name, iface->ifname, VTY_NEWLINE);
		return CMD_WARNING;
	}

	__clear_bit(FSWAN_INTERFACE_FL_SHUTDOWN_BIT, &iface->flags);
	return CMD_SUCCESS;
}


/*
 *	Show commands
 */
DEFUN(show_interface,
      show_interface_cmd,
      "show interface [STRING]",
      SHOW_STR
      "Dump declared interfaces; with a name, dump that interface only\n"
      "Interface name\n")
{
	struct interface *iface;

	if (argc >= 1) {
		iface = fswan_if_get(argv[0], false);
		if (!iface) {
			vty_out(vty, "%% Unknown interface '%s'%s"
				   , argv[0], VTY_NEWLINE);
			return CMD_WARNING;
		}
		fswan_if_show(iface, vty);
		return CMD_SUCCESS;
	}

	fswan_if_foreach(fswan_if_show, vty);
	return CMD_SUCCESS;
}

DEFUN(show_interface_stats_all,
      show_interface_stats_all_cmd,
      "show interface statistics",
      SHOW_STR
      "Interface\n"
      "Dump cumulative ethtool PHY counters and current rates for every"
      " declared interface\n")
{
	vty_out(vty, "%-16s  %14s  %14s  %14s  %14s  %14s  %14s  %14s  %14s%s",
		"Interface", "rx-packets", "tx-packets",
		"rx-bytes", "tx-bytes", "rx-bw", "tx-bw",
		"rx-pps", "tx-pps", VTY_NEWLINE);
	vty_out(vty, "%-16s  %14s  %14s  %14s  %14s  %14s  %14s  %14s  %14s%s",
		"----------------", "--------------", "--------------",
		"--------------", "--------------",
		"--------------", "--------------",
		"--------------", "--------------", VTY_NEWLINE);
	fswan_if_foreach(fswan_if_stats_show_summary, vty);
	return CMD_SUCCESS;
}

DEFUN(show_interface_stats,
      show_interface_stats_cmd,
      "show interface statistics WORD",
      SHOW_STR
      "Interface\n"
      "Dump per-interface ethtool PHY counters, derived rates and"
      " per-queue stats with the CPU each queue's IRQ is pinned to\n"
      "Interface name\n")
{
	struct interface *iface = fswan_if_get(argv[0], false);

	if (!iface) {
		vty_out(vty, "%% Unknown interface '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	fswan_if_stats_show_detail(vty, iface);
	return CMD_SUCCESS;
}

DEFUN(show_interface_rxq_topology,
      show_interface_rxq_topology_cmd,
      "show interface rx-queue topology",
      SHOW_STR
      "Interface\n"
      "Dump RX queue IRQ affinity grouped by NUMA node, plus a diagnostic"
      " of single-CPU pinning and per-CPU uniqueness\n")
{
	fswan_if_rxq_show(vty);
	return CMD_SUCCESS;
}

DEFUN(show_interface_topology,
      show_interface_topology_cmd,
      "show interface topology",
      SHOW_STR
      "Interface\n"
      "Enumerate every PCI ethernet adapter on the host and group them by"
      " NUMA node, showing each device's BDF, vendor:device ID and bound"
      " driver\n")
{
	struct pci_eth_dev *devs;
	int ndevs;

	devs = calloc(PCI_MAX_ETH_DEVS, sizeof(*devs));
	if (!devs)
		return CMD_WARNING;

	ndevs = pci_eth_dev_fetch(devs, PCI_MAX_ETH_DEVS);
	if (ndevs < 0) {
		vty_out(vty, "%% cannot enumerate PCI devices%s", VTY_NEWLINE);
		free(devs);
		return CMD_WARNING;
	}
	if (!ndevs) {
		vty_out(vty, "No PCI ethernet devices found%s", VTY_NEWLINE);
		free(devs);
		return CMD_SUCCESS;
	}

	pci_eth_dev_vty(vty, devs, ndevs);
	free(devs);
	return CMD_SUCCESS;
}


/*
 *	Configuration writer
 */
static int
interface_config_write(struct vty *vty)
{
	struct interface *iface;

	list_for_each_entry(iface, &daemon_data->interfaces, next) {
		vty_out(vty, "interface %s%s", iface->ifname, VTY_NEWLINE);
		if (iface->description[0])
			vty_out(vty, " description %s%s", iface->description, VTY_NEWLINE);
		if (iface->bpf_prog)
			vty_out(vty, " bpf-program %s%s"
				   , iface->bpf_prog->name, VTY_NEWLINE);
		vty_out(vty, " %sshutdown%s"
			   , __test_bit(FSWAN_INTERFACE_FL_SHUTDOWN_BIT, &iface->flags) ? "" : "no "
			   , VTY_NEWLINE);
		vty_out(vty, "!%s", VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
static int
cmd_ext_interface_install(void)
{
	install_element(CONFIG_NODE, &interface_cmd);
	install_element(CONFIG_NODE, &no_interface_cmd);

	install_default(INTERFACE_NODE);
	install_element(INTERFACE_NODE, &if_description_cmd);
	install_element(INTERFACE_NODE, &if_bpf_program_cmd);
	install_element(INTERFACE_NODE, &no_if_bpf_program_cmd);
	install_element(INTERFACE_NODE, &if_shutdown_cmd);
	install_element(INTERFACE_NODE, &if_no_shutdown_cmd);

	install_element(VIEW_NODE, &show_interface_cmd);
	install_element(VIEW_NODE, &show_interface_stats_all_cmd);
	install_element(VIEW_NODE, &show_interface_stats_cmd);
	install_element(VIEW_NODE, &show_interface_rxq_topology_cmd);
	install_element(VIEW_NODE, &show_interface_topology_cmd);
	install_element(ENABLE_NODE, &show_interface_cmd);
	install_element(ENABLE_NODE, &show_interface_stats_all_cmd);
	install_element(ENABLE_NODE, &show_interface_stats_cmd);
	install_element(ENABLE_NODE, &show_interface_rxq_topology_cmd);
	install_element(ENABLE_NODE, &show_interface_topology_cmd);

	return 0;
}

static struct cmd_node interface_node = {
	.node		= INTERFACE_NODE,
	.parent_node	= CONFIG_NODE,
	.prompt		= "%s(interface)# ",
	.config_write	= interface_config_write,
};

static struct cmd_ext cmd_ext_interface = {
	.node		= &interface_node,
	.install	= cmd_ext_interface_install,
};

static void __attribute__((constructor))
fswan_if_vty_init(void)
{
	cmd_ext_register(&cmd_ext_interface);
}
