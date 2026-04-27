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
#include "bitops.h"
#include "list_head.h"
#include "vty.h"
#include "command.h"
#include "fswan_data.h"
#include "fswan_if.h"
#include "fswan_bpf_prog.h"


/* Extern data */
extern struct data *daemon_data;


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
