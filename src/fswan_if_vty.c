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
#include <arpa/inet.h>

/* local includes */
#include "bitops.h"
#include "list_head.h"
#include "vty.h"
#include "vty_gauge.h"
#include "vty_graph.h"
#include "command.h"
#include "cpu.h"
#include "ethtool.h"
#include "pci.h"
#include "timer.h"
#include "inet_utils.h"
#include "fswan_data.h"
#include "fswan_cpu.h"
#include "fswan_if.h"
#include "fswan_if_rxq.h"
#include "fswan_bpf_prog.h"
#include "fswan_hairpin.h"
#include "fswan_flower.h"


/* Types */
struct dashboard_opts {
	char ifname[IF_NAMESIZE];
};

/* Extern data */
extern struct data *daemon_data;
extern struct cpu_load *cpu_load;


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

static void
stat_pair_vty(struct vty *vty, const char *l1, uint64_t v1,
	  const char *l2, uint64_t v2)
{
	vty_out(vty, "    %-24s %-14lu  %-24s %lu%s",
		l1, v1, l2, v2, VTY_NEWLINE);
}

static void
bandwidth_vty(struct vty *vty, const struct iface_rate *rx,
		const struct iface_rate *tx)
{
	char rxbw[20], txbw[20], rxpps[20], txpps[20];

	bw_format(rx->bw_bps, rxbw, sizeof(rxbw));
	bw_format(tx->bw_bps, txbw, sizeof(txbw));
	pps_format(rx->pps, rxpps, sizeof(rxpps));
	pps_format(tx->pps, txpps, sizeof(txpps));
	vty_out(vty, "  Bandwidth: rx:%s  tx:%s  |  PPS: rx:%s  tx:%s%s",
		rxbw, txbw, rxpps, txpps, VTY_NEWLINE);
}

static int
fswan_if_stats_summary_vty(struct interface *iface, void *arg)
{
	const struct ethtool_phy_stats *s = &iface->phy_stats;
	struct vty *vty = arg;
	char rxbw[20], txbw[20], rxpps[20], txpps[20];

	bw_format(iface->rx.bw_bps, rxbw, sizeof(rxbw));
	bw_format(iface->tx.bw_bps, txbw, sizeof(txbw));
	pps_format(iface->rx.pps, rxpps, sizeof(rxpps));
	pps_format(iface->tx.pps, txpps, sizeof(txpps));
	vty_out(vty, "%-16s  %14lu  %14lu  %14lu  %14lu  %14s  %14s  %14s  %14s%s",
		iface->ifname,
		s->rx_packets, s->tx_packets,
		s->rx_bytes, s->tx_bytes,
		rxbw, txbw, rxpps, txpps, VTY_NEWLINE);
	return 0;
}

static void
fswan_if_stats_phy_vty(struct vty *vty, const struct interface *iface)
{
	const struct ethtool_phy_stats *p = &iface->phy_stats;

	vty_out(vty, "  PHY counters:%s", VTY_NEWLINE);
	stat_pair_vty(vty, "rx_packets:", p->rx_packets, "tx_packets:", p->tx_packets);
	stat_pair_vty(vty, "rx_bytes:", p->rx_bytes, "tx_bytes:", p->tx_bytes);
	stat_pair_vty(vty, "rx_discards:", p->rx_discards, "tx_discards:", p->tx_discards);
	vty_out(vty, "    %-24s %lu%s",
		"tx_errors:", p->tx_errors, VTY_NEWLINE);
	bandwidth_vty(vty, &iface->rx, &iface->tx);
}

static void
fswan_if_stats_ipsec_vty(struct vty *vty, const struct interface *iface)
{
	const struct ethtool_ipsec_stats *s = &iface->ipsec_stats;

	if (!iface->ethtool_cache || !iface->ethtool_cache->n_ipsec)
		return;

	vty_out(vty, "  IPsec offload counters:%s", VTY_NEWLINE);
	stat_pair_vty(vty, "rx_pkts:", s->rx_pkts, "tx_pkts:", s->tx_pkts);
	stat_pair_vty(vty, "rx_bytes:", s->rx_bytes, "tx_bytes:", s->tx_bytes);
	stat_pair_vty(vty, "rx_drop_pkts:", s->rx_drop_pkts,
		       "tx_drop_pkts:", s->tx_drop_pkts);
	stat_pair_vty(vty, "rx_drop_bytes:", s->rx_drop_bytes,
		       "tx_drop_bytes:", s->tx_drop_bytes);
	bandwidth_vty(vty, &iface->ipsec_rx, &iface->ipsec_tx);
}

static void
fswan_if_stats_queues_vty(struct vty *vty, const struct interface *iface)
{
	uint32_t q, nr;
	int *cpu_per_q;

	if (!iface->queue_stats || !(iface->nr_rx_queues | iface->nr_tx_queues))
		return;

	nr = iface->nr_rx_queues > iface->nr_tx_queues ?
	     iface->nr_rx_queues : iface->nr_tx_queues;
	cpu_per_q = calloc(nr, sizeof(*cpu_per_q));
	if (!cpu_per_q)
		return;
	memset(cpu_per_q, -1, nr * sizeof(*cpu_per_q));
	fswan_if_rxq_cpu(iface, cpu_per_q, nr);

	vty_out(vty, "  Per-queue counters:%s", VTY_NEWLINE);
	vty_out(vty, "    %3s  %4s  %14s  %14s  %12s  %14s  %14s%s",
		"q", "cpu", "rx_packets", "rx_bytes", "rx_xdp_drop",
		"tx_packets", "tx_bytes", VTY_NEWLINE);
	for (q = 0; q < nr; q++) {
		const struct ethtool_q_stats *qs = &iface->queue_stats[q];
		vty_out(vty, "    %3u  %4d  %14lu  %14lu  %12lu  %14lu  %14lu%s",
			q, cpu_per_q[q],
			qs->rx_packets, qs->rx_bytes, qs->rx_xdp_drop,
			qs->tx_packets, qs->tx_bytes, VTY_NEWLINE);
	}
	free(cpu_per_q);
}

static void
fswan_if_stats_detail_vty(struct vty *vty, struct interface *iface)
{
	vty_out(vty, "Interface %s%s", iface->ifname, VTY_NEWLINE);
	fswan_if_stats_phy_vty(vty, iface);
	fswan_if_stats_ipsec_vty(vty, iface);
	fswan_if_stats_queues_vty(vty, iface);
	vty_out(vty, "%s", VTY_NEWLINE);
}

static int
fswan_if_vty(struct interface *iface, void *arg)
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
 *	Dashboard helpers
 */
static void
graph_bw_fmt(char *out, size_t sz, float v)
{
	bw_format((uint64_t)v, out, sz);
}

static void
graph_pps_fmt(char *out, size_t sz, float v)
{
	pps_format((uint64_t)v, out, sz);
}

/* One rate graph, sized to the full terminal width */
static void
dashboard_graph(struct vty *vty, const char *title,
		const struct gauge_history *h, float current, graph_fmt_fn fmt)
{
	struct graph_opts opts = {
		.color_mode = GAUGE_COLOR_TRUE,
		.height = 6,
		.label_width = 10,
		.fmt = fmt,
		.h = h,
	};
	int term_w = vty->width ? : 80;

	opts.width = term_w - opts.label_width - 2;
	if (opts.width < GRAPH_DEFAULT_WIDTH)
		opts.width = GRAPH_DEFAULT_WIDTH;

	vty_graph(vty, title, current, &opts);
	vty_out(vty, "%s", VTY_NEWLINE);
}

/* RX-queue CPU-load gauges, 2 per row, full terminal width */
static int
dashboard_rxq_gauges(struct vty *vty, const struct interface *iface)
{
	struct gauge_opts opts = {
		.style = GAUGE_BRAILLE_GRAPH,
		.color_mode = GAUGE_COLOR_TRUE,
		.label_width = 9,
		.left = "[",
		.right = "]",
	};
	int term_w = vty->width ? : 80;
	const struct fswan_percpu_metrics *m;
	int *cpu_per_q;
	int nrxq = (int)iface->nr_rx_queues;
	int q, cpu, n;
	char label[32];

	/* per-gauge overhead = label_w + 2 + left + right + " 100.0%" (7);
	 * two cells per row plus a 2-char separator */
	opts.width = (term_w - 2 - 2 * (opts.label_width + 11)) / 2;
	if (opts.width < 20)
		opts.width = 20;

	cpu_per_q = calloc(nrxq, sizeof(*cpu_per_q));
	if (!cpu_per_q)
		return 0;
	if (fswan_if_rxq_cpu(iface, cpu_per_q, nrxq) <= 0) {
		free(cpu_per_q);
		return 0;
	}

	n = 0;
	for (q = 0; q < nrxq; q++) {
		cpu = cpu_per_q[q];
		if (cpu < 0)
			continue;
		m = fswan_percpu_metrics_get(cpu);
		if (!m)
			continue;

		if (n & 1)
			vty_out(vty, "  ");

		snprintf(label, sizeof(label), " q%-2d/c%-3d", q, cpu);
		opts.h = &m->load_history;
		vty_gauge_emit(vty, label, cpu_load_get(cpu_load, cpu), &opts);
		n++;

		if (!(n & 1))
			vty_out(vty, "%s", VTY_NEWLINE);
	}
	if (n & 1)
		vty_out(vty, "%s", VTY_NEWLINE);

	free(cpu_per_q);
	return n;
}

/* Emit the 4-graph rate panel: BW RX, BW TX, PPS RX, PPS TX */
static void
dashboard_emit_graphs(struct vty *vty, const struct iface_rate *rx,
		      const struct iface_rate *tx, const char *bw_label,
		      const char *pps_label)
{
	char title[48];

	snprintf(title, sizeof(title), "%s (RX)", bw_label);
	dashboard_graph(vty, title, &rx->bw_history, (float)rx->bw_bps, graph_bw_fmt);
	snprintf(title, sizeof(title), "%s (TX)", bw_label);
	dashboard_graph(vty, title, &tx->bw_history, (float)tx->bw_bps, graph_bw_fmt);
	snprintf(title, sizeof(title), "%s (RX)", pps_label);
	dashboard_graph(vty, title, &rx->pps_history, (float)rx->pps, graph_pps_fmt);
	snprintf(title, sizeof(title), "%s (TX)", pps_label);
	dashboard_graph(vty, title, &tx->pps_history, (float)tx->pps, graph_pps_fmt);
}

/* Resolve the iface named in vty->priv. Looks up fresh every call so a
 * mid-monitor deletion from another vty session is reported instead of
 * dereferencing a freed pointer. */
static struct interface *
dashboard_resolve(struct vty *vty)
{
	const struct dashboard_opts *opts = vty->priv;
	struct interface *iface;

	iface = fswan_if_get(opts->ifname, false);
	if (!iface)
		vty_out(vty, "%% Interface '%s' no longer exists%s",
			opts->ifname, VTY_NEWLINE);
	return iface;
}

int
fswan_if_dashboard_vty(struct vty *vty)
{
	struct interface *iface = dashboard_resolve(vty);

	if (!iface)
		return -1;

	vty_out(vty, "Interface %s  ifindex:%d  rx_queues:%u%s%s",
		iface->ifname, iface->ifindex, iface->nr_rx_queues,
		VTY_NEWLINE, VTY_NEWLINE);

	dashboard_emit_graphs(vty, &iface->rx, &iface->tx,
			      "Bandwidth", "Packets/sec");

	vty_out(vty, "RX queues  (CPU load of pinned CPU)%s", VTY_NEWLINE);

	if (!cpu_load) {
		vty_out(vty, "%% CPU monitoring not available%s", VTY_NEWLINE);
		return 0;
	}
	if (!iface->nr_rx_queues) {
		vty_out(vty, "%% Interface has no RX queues%s", VTY_NEWLINE);
		return 0;
	}
	if (!dashboard_rxq_gauges(vty, iface))
		vty_out(vty, "%% No RX queue CPU bindings available for %s%s",
			iface->ifname, VTY_NEWLINE);

	return 0;
}

int
fswan_if_ipsec_vty(struct vty *vty)
{
	struct interface *iface = dashboard_resolve(vty);

	if (!iface)
		return -1;

	if (!iface->ethtool_cache || !iface->ethtool_cache->n_ipsec) {
		vty_out(vty, "%% No IPsec offload counters for '%s'%s",
			iface->ifname, VTY_NEWLINE);
		return -1;
	}

	vty_out(vty, "Interface %s  ifindex:%d  IPsec offload%s%s",
		iface->ifname, iface->ifindex, VTY_NEWLINE, VTY_NEWLINE);

	dashboard_emit_graphs(vty, &iface->ipsec_rx, &iface->ipsec_tx,
			      "IPsec Bandwidth", "IPsec Packets/sec");
	return 0;
}

/* Allocate an opts payload for the monitor refresh thread to own */
void *
fswan_if_dashboard_opts_alloc(const char *ifname)
{
	struct dashboard_opts *opts = calloc(1, sizeof(*opts));

	if (!opts)
		return NULL;
	snprintf(opts->ifname, sizeof(opts->ifname), "%s", ifname);
	return opts;
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
      " driver mode; lazy-loads the BPF object if it isn't running yet\n")
{
	struct interface *iface = vty->index;

	if (iface->bpf_prog &&
	    fswan_bpf_prog_attach(iface->bpf_prog, iface)) {
		vty_out(vty, "%% Failed to attach bpf-program '%s' to %s%s"
			   , iface->bpf_prog->name, iface->ifname, VTY_NEWLINE);
		return CMD_WARNING;
	}

	__clear_bit(FSWAN_INTERFACE_FL_SHUTDOWN_BIT, &iface->flags);
	return CMD_SUCCESS;
}

DEFUN(if_hairpin_to_nexthop,
      if_hairpin_to_nexthop_cmd,
      "hairpin-to-nexthop A.B.C.D",
      "Pre-resolve the next-hop MAC for inbound (post-IPsec-decap) traffic"
      " on this interface and skip the per-packet bpf_fib_lookup. The"
      " reformat is rebuilt automatically when the kernel's ARP entry"
      " changes; until first resolution, the BPF datapath falls back to"
      " bpf_fib_lookup\n"
      "IPv4 address of the next-hop gateway\n")
{
	struct interface *iface = vty->index;
	uint32_t addr;

	if (inet_pton(AF_INET, argv[0], &addr) != 1) {
		vty_out(vty, "%% Invalid IPv4 address '%s'%s"
			   , argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (fswan_hairpin_set(iface, addr))
		vty_out(vty, "%% Cannot resolve nexthop %s on %s!"
			     " Will retry on neigh or route update%s"
			   , argv[0], iface->ifname, VTY_NEWLINE);

	return CMD_SUCCESS;
}

DEFUN(no_if_hairpin_to_nexthop,
      no_if_hairpin_to_nexthop_cmd,
      "no hairpin-to-nexthop",
      "Drop the hairpin nexthop binding; subsequent inbound packets fall back"
      " to the regular fib_lookup path\n")
{
	struct interface *iface = vty->index;

	fswan_hairpin_clear(iface);
	return CMD_SUCCESS;
}

DEFUN(if_flower_mode,
      if_flower_mode_cmd,
      "flower-mode",
      "Replace the XDP egress path with mlx5 TC flower HW offload."
      " Outbound XFRM packet-mode policies on this interface are mirrored to"
      " clsact ingress flower rules with skip_sw and a mirred-egress redirect"
      " into the egress IPsec chain. mlx5 driver only.\n")
{
	struct interface *iface = vty->index;

	if (fswan_flower_enable(iface)) {
		vty_out(vty, "%% flower-mode activation failed on %s%s"
			   , iface->ifname, VTY_NEWLINE);
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}

ALIAS(if_flower_mode,
      if_furious_mode_cmd,
      "furious-mode",
      "Alias of flower-mode\n")

DEFUN(no_if_flower_mode,
      no_if_flower_mode_cmd,
      "no flower-mode",
      "Tear down the TC flower HW offload state on this interface, removing"
      " every installed filter and the clsact qdisc\n")
{
	struct interface *iface = vty->index;

	fswan_flower_disable(iface);
	return CMD_SUCCESS;
}

ALIAS(no_if_flower_mode,
      no_if_furious_mode_cmd,
      "no furious-mode",
      "Alias of no flower-mode\n")


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
		fswan_if_vty(iface, vty);
		return CMD_SUCCESS;
	}

	fswan_if_foreach(fswan_if_vty, vty);
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
	fswan_if_foreach(fswan_if_stats_summary_vty, vty);
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

	fswan_if_stats_detail_vty(vty, iface);
	return CMD_SUCCESS;
}

DEFUN(show_interface_stats_csv,
      show_interface_stats_csv_cmd,
      "show interface stats-csv WORD",
      SHOW_STR
      "Interface\n"
      "Emit one TSV row with the current rates and per-rx-queue CPU load,"
      " intended for an external bench harness that loops every N seconds"
      " and appends to a file. Columns: ts_ns, ifname, rx_bps, tx_bps,"
      " rx_pps, tx_pps, then (cpu, load) pairs for each bound rx-queue\n"
      "Interface name\n")
{
	struct interface *iface = fswan_if_get(argv[0], false);
	int nrxq, q, cpu;

	if (!iface) {
		vty_out(vty, "%% Unknown interface '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty_out(vty, "%lu\t%s\t%lu\t%lu\t%lu\t%lu",
		(unsigned long)clock_gettime_ns(CLOCK_REALTIME),
		iface->ifname,
		(unsigned long)iface->rx.bw_bps,
		(unsigned long)iface->tx.bw_bps,
		(unsigned long)iface->rx.pps,
		(unsigned long)iface->tx.pps);

	nrxq = (int)iface->nr_rx_queues;
	if (nrxq && cpu_load) {
		int cpu_per_q[nrxq];

		memset(cpu_per_q, -1, sizeof(cpu_per_q));
		fswan_if_rxq_cpu(iface, cpu_per_q, nrxq);
		for (q = 0; q < nrxq; q++) {
			cpu = cpu_per_q[q];
			if (cpu < 0)
				continue;
			vty_out(vty, "\t%d\t%.4f", cpu, cpu_load_get(cpu_load, cpu));
		}
	}

	vty_out(vty, "%s", VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN(show_interface_dashboard,
      show_interface_dashboard_cmd,
      "show interface dashboard WORD",
      SHOW_STR
      "Interface\n"
      "Render a live activity dashboard for one interface: stacked rx/tx"
      " bandwidth and pps graphs over the rate-history ring, plus per-rx-queue"
      " CPU-load gauges for the CPU pinned to each queue's IRQ\n"
      "Interface name\n")
{
	struct dashboard_opts opts;
	int ret;

	if (!fswan_if_get(argv[0], false)) {
		vty_out(vty, "%% Unknown interface '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	snprintf(opts.ifname, sizeof(opts.ifname), "%s", argv[0]);
	vty->priv = &opts;
	ret = fswan_if_dashboard_vty(vty);
	vty->priv = NULL;
	return ret ? CMD_WARNING : CMD_SUCCESS;
}

DEFUN(show_interface_ipsec,
      show_interface_ipsec_cmd,
      "show interface ipsec WORD",
      SHOW_STR
      "Interface\n"
      "Render IPsec offload activity for one interface: stacked rx/tx"
      " bandwidth and pps graphs over the IPsec rate-history ring\n"
      "Interface name\n")
{
	struct dashboard_opts opts;
	int ret;

	if (!fswan_if_get(argv[0], false)) {
		vty_out(vty, "%% Unknown interface '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	snprintf(opts.ifname, sizeof(opts.ifname), "%s", argv[0]);
	vty->priv = &opts;
	ret = fswan_if_ipsec_vty(vty);
	vty->priv = NULL;
	return ret ? CMD_WARNING : CMD_SUCCESS;
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
		if (iface->hairpin)
			vty_out(vty, " hairpin-to-nexthop %u.%u.%u.%u%s"
				   , NIPQUAD(iface->hairpin->nh_addr), VTY_NEWLINE);
		if (iface->flower)
			vty_out(vty, " flower-mode%s", VTY_NEWLINE);
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
	install_element(INTERFACE_NODE, &if_hairpin_to_nexthop_cmd);
	install_element(INTERFACE_NODE, &no_if_hairpin_to_nexthop_cmd);
	install_element(INTERFACE_NODE, &if_flower_mode_cmd);
	install_element(INTERFACE_NODE, &if_furious_mode_cmd);
	install_element(INTERFACE_NODE, &no_if_flower_mode_cmd);
	install_element(INTERFACE_NODE, &no_if_furious_mode_cmd);
	install_element(INTERFACE_NODE, &if_shutdown_cmd);
	install_element(INTERFACE_NODE, &if_no_shutdown_cmd);

	install_element(VIEW_NODE, &show_interface_cmd);
	install_element(VIEW_NODE, &show_interface_stats_all_cmd);
	install_element(VIEW_NODE, &show_interface_stats_cmd);
	install_element(VIEW_NODE, &show_interface_stats_csv_cmd);
	install_element(VIEW_NODE, &show_interface_dashboard_cmd);
	install_element(VIEW_NODE, &show_interface_ipsec_cmd);
	install_element(VIEW_NODE, &show_interface_rxq_topology_cmd);
	install_element(VIEW_NODE, &show_interface_topology_cmd);
	install_element(ENABLE_NODE, &show_interface_cmd);
	install_element(ENABLE_NODE, &show_interface_stats_all_cmd);
	install_element(ENABLE_NODE, &show_interface_stats_cmd);
	install_element(ENABLE_NODE, &show_interface_stats_csv_cmd);
	install_element(ENABLE_NODE, &show_interface_dashboard_cmd);
	install_element(ENABLE_NODE, &show_interface_ipsec_cmd);
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
