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
#include <net/if.h>

/* local includes */
#include "memory.h"
#include "bitops.h"
#include "list_head.h"
#include "vty.h"
#include "command.h"
#include "fswan_data.h"
#include "fswan_bpf.h"
#include "fswan_bpf_xfrm.h"


/* Extern data */
extern struct data *daemon_data;


/*
 *	Command
 */
DEFUN(bpf,
      bpf_cmd,
      "bpf",
      "Enter the BPF subsystem to load and manage XDP/eBPF programs and their maps\n")
{
	vty->node = BPF_PROG_NODE;
	return CMD_SUCCESS;
}

DEFUN(bpf_xdp_xfrm,
      bpf_xdp_xfrm_cmd,
      "xdp-xfrm STRING object-file STRING interface STRING [progname STRING]",
      "Load the XFRM offload eBPF program and attach it to a netdev in XDP driver mode\n"
      "Symbolic label identifying this loaded program instance for later reference\n"
      "Specify the compiled BPF object file containing the XFRM offload program\n"
      "Filesystem path to the .bpf object (typically xfrm_offload.bpf)\n"
      "Network interface that will run the XDP program in driver/native mode\n"
      "Interface name (e.g. eth0) where the XDP program is attached\n"
      "Override the BPF program/section name to attach\n"
      "Section name inside the object file (default: first XDP program found)\n")
{
	struct list_head *l = &daemon_data->bpf_progs;
	struct fswan_bpf_opts *opts;
	int err = 0;

	if (fswan_bpf_opts_exist(l, argc, argv)) {
		vty_out(vty, "%% XDP BPF program already loaded on interface %s!!!%s"
			   , argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	opts = fswan_bpf_opts_alloc(BPF_PROG_XDP, fswan_xdp_unload);
	err = (err) ? : fswan_bpf_opts_load(opts, vty, argc, argv, fswan_bpf_xfrm_load);
	err = (err) ? : fswan_bpf_xfrm_stats_init(opts);
	if (err) {
		FREE(opts);
		return CMD_WARNING;
	}

	fswan_bpf_opts_add(opts, l);
	__set_bit(FSWAN_FL_XDP_XFRM_LOADED_BIT, &daemon_data->flags);
	return CMD_SUCCESS;
}

DEFUN(no_bpf_xdp_xfrm,
      no_bpf_xdp_xfrm_cmd,
      "no xdp-xfrm STRING object-file STRING interface STRING",
      "Detach and unload a previously loaded XDP XFRM offload program\n"
      "Label of the program instance to remove (must match the label used at load time)\n"
      "Object file argument used at load time\n"
      "Path to the .bpf object (must match the load arguments)\n"
      "Interface argument used at load time\n"
      "Interface name where the program is currently attached\n")
{
	struct list_head *l = &daemon_data->bpf_progs;
	struct fswan_bpf_opts *opts;

	opts = fswan_bpf_opts_exist(l, argc, argv);
	if (!opts) {
		vty_out(vty, "%% unknown XDP BPF program %s on interface %s !!!%s"
			   , argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	fswan_bpf_opts_del(opts);

	if (list_empty(l))
		__clear_bit(FSWAN_FL_XDP_XFRM_LOADED_BIT, &daemon_data->flags);
	return CMD_SUCCESS;
}

/* Configuration writer */
static int
fswan_bpf_opts_config_write(struct vty *vty, struct fswan_bpf_opts *opts)
{
	char ifname[IF_NAMESIZE];
	const char *progname = opts->progname[0] ? opts->progname : NULL;

	vty_out(vty, " xdp-xfrm %s object-file %s interface %s%s%s%s"
		   , opts->label
		   , opts->filename
		   , if_indextoname(opts->ifindex, ifname)
		   , progname ? " progname " : ""
		   , progname ? progname : ""
		   , VTY_NEWLINE);
	return 0;
}

static int
bpf_config_write(struct vty *vty)
{
	struct fswan_bpf_opts *opts;

	if (list_empty(&daemon_data->bpf_progs))
		return CMD_SUCCESS;

	vty_out(vty, "bpf%s", VTY_NEWLINE);
	list_for_each_entry(opts, &daemon_data->bpf_progs, next)
		fswan_bpf_opts_config_write(vty, opts);
	vty_out(vty, "!%s", VTY_NEWLINE);

	if (__test_bit(FSWAN_FL_XDP_XFRM_DISABLE_SRC_MATCH_BIT, &daemon_data->flags))
		vty_out(vty, "disable-xdp-xfrm-source-matching%s", VTY_NEWLINE);
	if (__test_bit(FSWAN_FL_XFRM_KERNEL_LOADED_BIT, &daemon_data->flags))
		vty_out(vty, "load-existing-xfrm-policy%s", VTY_NEWLINE);
	if (__test_bit(FSWAN_FL_XDP_XFRM_DISABLE_STATS_BIT, &daemon_data->flags))
		vty_out(vty, "disable-xdp-xfrm-offload-statistics%s", VTY_NEWLINE);
	vty_out(vty, "!%s", VTY_NEWLINE);

	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
static int
cmd_ext_bpf_install(void)
{
	/* Install BPF commands. */
	install_element(CONFIG_NODE, &bpf_cmd);

	install_default(BPF_PROG_NODE);
	install_element(BPF_PROG_NODE, &bpf_xdp_xfrm_cmd);
	install_element(BPF_PROG_NODE, &no_bpf_xdp_xfrm_cmd);

	return 0;
}

static struct cmd_node bpf_node = {
	.node		= BPF_PROG_NODE,
	.parent_node	= CONFIG_NODE,
	.prompt		= "%s(bpf)# ",
	.config_write	= bpf_config_write,
};

static struct cmd_ext cmd_ext_bpf = {
	.node		= &bpf_node,
	.install	= cmd_ext_bpf_install,
};

static void __attribute__((constructor))
fswan_bpf_vty_init(void)
{
	cmd_ext_register(&cmd_ext_bpf);
}
