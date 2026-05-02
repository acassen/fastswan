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

/* local includes */
#include <stdbool.h>

#include "bitops.h"
#include "vty.h"
#include "command.h"
#include "fswan_data.h"
#include "fswan_bpf_xfrm.h"
#include "fswan_netlink.h"


/* Extern data */
extern struct data *daemon_data;


/*
 *	Helpers
 */
static bool
xdp_xfrm_is_loaded(struct vty *vty)
{
	if (__test_bit(FSWAN_FL_XDP_XFRM_LOADED_BIT, &daemon_data->flags))
		return true;

	vty_out(vty, "%% XDP XFRM offload is not configured. Ignoring%s"
		   , VTY_NEWLINE);
	return false;
}

static int
xdp_xfrm_flag_set(struct vty *vty, unsigned long bit, const char *already)
{
	if (!xdp_xfrm_is_loaded(vty))
		return CMD_WARNING;

	if (__test_bit(bit, &daemon_data->flags)) {
		vty_out(vty, "%% %s. Ignoring%s", already, VTY_NEWLINE);
		return CMD_WARNING;
	}

	__set_bit(bit, &daemon_data->flags);
	return CMD_SUCCESS;
}

static int
xdp_xfrm_flag_clear(struct vty *vty, unsigned long bit, const char *already)
{
	if (!xdp_xfrm_is_loaded(vty))
		return CMD_WARNING;

	if (!__test_bit(bit, &daemon_data->flags)) {
		vty_out(vty, "%% %s. Ignoring%s", already, VTY_NEWLINE);
		return CMD_WARNING;
	}

	__clear_bit(bit, &daemon_data->flags);
	return CMD_SUCCESS;
}

static int
xdp_xfrm_show(struct vty *vty, int (*fn)(struct vty *), const char *what)
{
	if (!xdp_xfrm_is_loaded(vty))
		return CMD_WARNING;

	if (fn(vty)) {
		vty_out(vty, "%% Error displaying XDP XFRM %s%s"
			   , what, VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}


/*
 *	Global configuration commands
 */
DEFUN(load_existing_xfrm_policy,
      load_existing_xfrm_policy_cmd,
      "load-existing-xfrm-policy",
      "Bootstrap the XDP fast path by mirroring all currently installed"
      " kernel XFRM policies into the BPF LPM map"
      " (sends an XFRM_MSG_GETPOLICY netlink dump and inserts each policy)\n")
{
	if (!xdp_xfrm_is_loaded(vty))
		return CMD_WARNING;

	if (__test_bit(FSWAN_FL_XFRM_KERNEL_LOADED_BIT, &daemon_data->flags)) {
		vty_out(vty, "%% Existing kernel XFRM policy already loaded. Ignoring%s"
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (netlink_xfrm_lookup()) {
		vty_out(vty, "%% Error requesting kernel for existing XFRM policies%s"
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	__set_bit(FSWAN_FL_XFRM_KERNEL_LOADED_BIT, &daemon_data->flags);
	return CMD_SUCCESS;
}

DEFUN(disable_xdp_xfrm_offload_stats,
      disable_xdp_xfrm_stats_offload_cmd,
      "disable-xdp-xfrm-offload-statistics",
      "Disable per-policy packet/byte counter accounting in the XDP fast path;"
      " reduces per-packet overhead at the cost of losing visibility from 'show"
      " xdp xfrm offload ...' counters\n")
{
	return xdp_xfrm_flag_set(vty, FSWAN_FL_XDP_XFRM_DISABLE_STATS_BIT,
				 "XDP XFRM Statistics already disabled");
}

DEFUN(no_disable_xdp_xfrm_offload_stats,
      no_disable_xdp_xfrm_stats_offload_cmd,
      "no disable-xdp-xfrm-offload-statistics",
      "Re-enable per-policy packet/byte counter accounting in the XDP fast path"
      " (default behaviour)\n")
{
	return xdp_xfrm_flag_clear(vty, FSWAN_FL_XDP_XFRM_DISABLE_STATS_BIT,
				   "XDP XFRM Statistics already enabled");
}

/*
 *	Show commands
 */
DEFUN(show_xdp_xfrm_offload_policy,
      show_xdp_xfrm_offload_policy_cmd,
      "show xdp xfrm offload policy",
      SHOW_STR
      "Dump the destination prefixes currently installed in the XDP XFRM LPM map,"
      " with their source-prefix list and per-policy flags\n")
{
	return xdp_xfrm_show(vty, fswan_xfrm_policy_vty, "policies");
}

DEFUN(show_xdp_xfrm_offload_policy_stats,
      show_xdp_xfrm_offload_policy_stats_cmd,
      "show xdp xfrm offload policy statistcs",
      SHOW_STR
      "Dump per-policy / per-source-prefix packet and byte counters"
      " collected by the XDP fast path\n")
{
	return xdp_xfrm_show(vty, fswan_xfrm_policy_stats_vty, "policies");
}

/*
 *	VTY init
 */
static int
cmd_ext_fswan_install(void)
{
	/* Install Global commands */
	install_element(CONFIG_NODE, &load_existing_xfrm_policy_cmd);
	install_element(CONFIG_NODE, &disable_xdp_xfrm_stats_offload_cmd);
	install_element(CONFIG_NODE, &no_disable_xdp_xfrm_stats_offload_cmd);
	/* Install Global show commands */
	install_element(VIEW_NODE, &show_xdp_xfrm_offload_policy_cmd);
	install_element(VIEW_NODE, &show_xdp_xfrm_offload_policy_stats_cmd);
	install_element(ENABLE_NODE, &show_xdp_xfrm_offload_policy_cmd);
	install_element(ENABLE_NODE, &show_xdp_xfrm_offload_policy_stats_cmd);

	return 0;
}

static struct cmd_ext cmd_ext_fswan = {
	.install	= cmd_ext_fswan_install,
};

static void __attribute__((constructor))
fswan_vty_init(void)
{
	cmd_ext_register(&cmd_ext_fswan);
}
