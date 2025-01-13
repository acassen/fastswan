/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Soft:        The main goal of this project is to provide a fast data-path
 *              for the Linux Kernel XFRM layer. Some NIC vendors offer IPSEC
 *              acceleration via a Crypto mode or a Packet mode. In Packet
 *              mode, all IPSEC ESP operations are done by the hardware to
 *              offload the kernel for crypto and packet handling. To further
 *              increase perfs we implement kernel routing offload via XDP.
 *              A XFRM kernel netlink reflector is dynamically andi
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
 * Copyright (C) 2025 Alexandre Cassen, <acassen@gmail.com>
 */

/* system includes */
#include <pthread.h>
#include <sys/stat.h>
#include <net/if.h>
#include <errno.h>

/* local includes */
#include "fastswan.h"


/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;

static int bpf_config_write(vty_t *vty);
cmd_node_t bpf_node = {
        .node = BPF_NODE,
        .parent_node = CONFIG_NODE,
        .prompt = "%s(bpf)# ",
        .config_write = bpf_config_write,
};


/*
 *	Command
 */
DEFUN(bpf,
      bpf_cmd,
      "bpf",
      "Configure BPF progs\n")
{
	vty->node = BPF_NODE;
	return CMD_SUCCESS;
}

DEFUN(bpf_xdp_xfrm,
      bpf_xdp_xfrm_cmd,
      "xdp-xfrm STRING object-file STRING interface STRING [progname STRING]",
      "XDP-XFRM\n"
      "label\n"
      "BPF object file\n"
      "PATH to BPF prog\n"
      "interface to attach to\n"
      "interface name\n"
      "BPF Program Name\n"
      "Name\n")
{
	list_head_t *l = &daemon_data->bpf_progs;
	fswan_bpf_opts_t *opts;
	int err = 0;

	if (fswan_bpf_opts_exist(l, argc, argv)) {
		vty_out(vty, "%% XDP BPF program already loaded on interface %s!!!%s"
			   , argv[1]
			   , VTY_NEWLINE);
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
      "XDP-XFRM\n"
      "label\n"
      "BPF object file\n"
      "PATH to BPF prog\n"
      "interface to attach to\n"
      "interface name\n")
{
	list_head_t *l = &daemon_data->bpf_progs;
	fswan_bpf_opts_t *opts;

	if (argc < 2) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	opts = fswan_bpf_opts_exist(l, argc, argv);
	if (!opts) {
		vty_out(vty, "%% unknown XDP BPF program %s on interface %s !!!%s"
			   , argv[0], argv[1]
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	fswan_bpf_opts_del(opts);

	if (list_empty(l))
		__clear_bit(FSWAN_FL_XDP_XFRM_LOADED_BIT, &daemon_data->flags);
	return CMD_SUCCESS;
}

DEFUN(load_existing_xfrm_policy,
      load_existing_xfrm_policy_cmd,
      "load-existing-xfrm-policy",
      "Load existing kernel xfrm policy\n")
{
	int err;

	if (!__test_bit(FSWAN_FL_XDP_XFRM_LOADED_BIT, &daemon_data->flags)) {
		vty_out(vty, "%% XDP XFRM offload is not configured. Ignoring%s"
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (__test_bit(FSWAN_FL_XFRM_KERNEL_LOADED_BIT, &daemon_data->flags)) {
		vty_out(vty, "%% Existing kernel XFRM policy already loaded. Ignoring%s"
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	err = netlink_xfrm_lookup();
	if (err) {
		vty_out(vty, "%% Error requesting kernel for existing XFRM policies%s"
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	__set_bit(FSWAN_FL_XFRM_KERNEL_LOADED_BIT, &daemon_data->flags);
	return CMD_SUCCESS;
}

DEFUN(show_xdp_xfrm_offload_policy,
      show_xdp_xfrm_offload_policy_cmd,
      "show xdp xfrm offload policy",
      SHOW_STR
      "XDP XFRM offload policy\n")
{
	int err;

	if (!__test_bit(FSWAN_FL_XDP_XFRM_LOADED_BIT, &daemon_data->flags)) {
		vty_out(vty, "%% XDP XFRM offload is not configured. Ignoring%s"
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	err = fswan_xfrm_policy_vty(vty);
	if (err) {
		vty_out(vty, "%% Error displaying XDP XFRM policies%s"
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(show_xdp_xfrm_offload_stats,
      show_xdp_xfrm_offload_stats_cmd,
      "show xdp xfrm offload statistics",
      SHOW_STR
      "XDP XFRM offload statistics\n")
{
	int err;

	if (!__test_bit(FSWAN_FL_XDP_XFRM_LOADED_BIT, &daemon_data->flags)) {
		vty_out(vty, "%% XDP XFRM offload is not configured. Ignoring%s"
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	err = fswan_xfrm_stats_vty(vty);
	if (err) {
		vty_out(vty, "%% Error displaying XDP XFRM statistics%s"
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}


/* Configuration writer */
static int
fswan_bpf_opts_config_write(vty_t *vty, fswan_bpf_opts_t *opts)
{
	char ifname[IF_NAMESIZE];

	if (opts->progname[0]) {
		vty_out(vty, " xdp-xfrm %s object-file %s interface %s progname %s%s"
			   , opts->label
			   , opts->filename
			   , if_indextoname(opts->ifindex, ifname)
			   , opts->progname
			   , VTY_NEWLINE);
		return 0;
	}

	vty_out(vty, " xdp-xfrm %s object-file %s interface %s%s"
		   , opts->label
		   , opts->filename
		   , if_indextoname(opts->ifindex, ifname)
		   , VTY_NEWLINE);
	return 0;
}

static int
bpf_config_write(vty_t *vty)
{
	fswan_bpf_opts_t *opts;

	if (list_empty(&daemon_data->bpf_progs))
		return CMD_SUCCESS;

	vty_out(vty, "bpf%s", VTY_NEWLINE);
	list_for_each_entry(opts, &daemon_data->bpf_progs, next)
		fswan_bpf_opts_config_write(vty, opts);
	vty_out(vty, "!%s", VTY_NEWLINE);

	if (__test_bit(FSWAN_FL_XFRM_KERNEL_LOADED_BIT, &daemon_data->flags)) {
		vty_out(vty, "load-existing-xfrm-policy%s", VTY_NEWLINE);
		vty_out(vty, "!%s", VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
int
fswan_bpf_vty_init(void)
{

	/* Install BPF commands. */
	install_node(&bpf_node);
	install_element(CONFIG_NODE, &bpf_cmd);

	install_default(BPF_NODE);
	install_element(BPF_NODE, &bpf_xdp_xfrm_cmd);
	install_element(BPF_NODE, &no_bpf_xdp_xfrm_cmd);

	/* Install global configuration commands */
	install_element(CONFIG_NODE, &load_existing_xfrm_policy_cmd);

	/* Install show commands */
	install_element(VIEW_NODE, &show_xdp_xfrm_offload_policy_cmd);
	install_element(VIEW_NODE, &show_xdp_xfrm_offload_stats_cmd);
	install_element(ENABLE_NODE, &show_xdp_xfrm_offload_policy_cmd);
	install_element(ENABLE_NODE, &show_xdp_xfrm_offload_stats_cmd);

	return 0;
}
