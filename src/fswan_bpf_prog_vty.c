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
#include "fswan_bpf_prog.h"


/* Extern data */
extern struct data *daemon_data;


/*
 *	Helpers
 */
static struct fswan_bpf_prog *
vty_bpf_prog_lookup(struct vty *vty, const char *name)
{
	struct fswan_bpf_prog *p = fswan_bpf_prog_get(name);

	if (!p)
		vty_out(vty, "%% Unknown bpf-program '%s'%s", name, VTY_NEWLINE);
	return p;
}


/*
 *	Commands
 */
DEFUN(bpf_program,
      bpf_program_cmd,
      "bpf-program STRING",
      "Declare or enter the configuration block of a named BPF program; programs"
      " are stored as `struct fswan_bpf_prog` in `daemon_data->bpf_progs` and"
      " carry the path, optional section name and lifecycle flag\n"
      "Symbolic name (referenced later from `interface` blocks)\n")
{
	struct fswan_bpf_prog *p;

	p = fswan_bpf_prog_get(argv[0]);
	if (!p)
		p = fswan_bpf_prog_alloc(argv[0]);

	vty->node = BPF_PROG_NODE;
	vty->index = p;
	return CMD_SUCCESS;
}

DEFUN(no_bpf_program,
      no_bpf_program_cmd,
      "no bpf-program STRING",
      "Detach every interface using this program, unload the BPF object,"
      " then drop the declaration\n"
      "Name of the bpf-program to remove\n")
{
	struct fswan_bpf_prog *p = vty_bpf_prog_lookup(vty, argv[0]);

	if (!p)
		return CMD_WARNING;

	fswan_bpf_prog_destroy(p);
	return CMD_SUCCESS;
}

DEFUN(bpf_prog_description,
      bpf_prog_description_cmd,
      "description LINE",
      "Free-form human-readable label stored alongside the bpf-program;"
      " purely informational, surfaced by config write and show commands\n"
      "Description text\n")
{
	struct fswan_bpf_prog *p = vty->index;

	strlcpy(p->description, argv[0], sizeof(p->description) - 1);
	return CMD_SUCCESS;
}

DEFUN(bpf_prog_path,
      bpf_prog_path_cmd,
      "path STRING",
      "Filesystem path of the compiled .bpf object that will be loaded"
      " by libbpf when this program is brought up (`no shutdown`)\n"
      "Absolute path to the .bpf object file\n")
{
	struct fswan_bpf_prog *p = vty->index;

	strlcpy(p->path, argv[0], sizeof(p->path) - 1);
	return CMD_SUCCESS;
}

DEFUN(bpf_prog_progname,
      bpf_prog_progname_cmd,
      "prog-name STRING",
      "Override the BPF section/function name to attach when the object"
      " contains several programs; defaults to the first XDP program found\n"
      "Section name inside the .bpf object\n")
{
	struct fswan_bpf_prog *p = vty->index;

	strlcpy(p->progname, argv[0], sizeof(p->progname) - 1);
	return CMD_SUCCESS;
}

DEFUN(bpf_prog_shutdown,
      bpf_prog_shutdown_cmd,
      "shutdown",
      "Detach every interface bound to this program and unload its BPF object"
      " from the kernel; declaration is preserved\n")
{
	struct fswan_bpf_prog *p = vty->index;

	fswan_bpf_prog_unload(p);
	return CMD_SUCCESS;
}

DEFUN(bpf_prog_no_shutdown,
      bpf_prog_no_shutdown_cmd,
      "no shutdown",
      "Open the .bpf object set by `path`, run the kernel verifier and wire"
      " the XFRM offload maps; required before any interface can attach\n")
{
	struct fswan_bpf_prog *p = vty->index;

	if (fswan_bpf_prog_load(p)) {
		vty_out(vty, "%% Failed to load bpf-program '%s' from %s%s"
			   , p->name, p->path, VTY_NEWLINE);
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}


/*
 *	Configuration writer
 */
static int
bpf_prog_config_write(struct vty *vty)
{
	struct fswan_bpf_prog *p;

	list_for_each_entry(p, &daemon_data->bpf_progs, next) {
		vty_out(vty, "bpf-program %s%s", p->name, VTY_NEWLINE);
		if (p->description[0])
			vty_out(vty, " description %s%s", p->description, VTY_NEWLINE);
		if (p->path[0])
			vty_out(vty, " path %s%s", p->path, VTY_NEWLINE);
		if (p->progname[0])
			vty_out(vty, " prog-name %s%s", p->progname, VTY_NEWLINE);
		vty_out(vty, " %sshutdown%s"
			   , __test_bit(FSWAN_BPF_PROG_FL_SHUTDOWN_BIT, &p->flags) ? "" : "no "
			   , VTY_NEWLINE);
		vty_out(vty, "!%s", VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
static int
cmd_ext_bpf_prog_install(void)
{
	install_element(CONFIG_NODE, &bpf_program_cmd);
	install_element(CONFIG_NODE, &no_bpf_program_cmd);

	install_default(BPF_PROG_NODE);
	install_element(BPF_PROG_NODE, &bpf_prog_description_cmd);
	install_element(BPF_PROG_NODE, &bpf_prog_path_cmd);
	install_element(BPF_PROG_NODE, &bpf_prog_progname_cmd);
	install_element(BPF_PROG_NODE, &bpf_prog_shutdown_cmd);
	install_element(BPF_PROG_NODE, &bpf_prog_no_shutdown_cmd);

	return 0;
}

static struct cmd_node bpf_prog_node = {
	.node		= BPF_PROG_NODE,
	.parent_node	= CONFIG_NODE,
	.prompt		= "%s(bpf-program)# ",
	.config_write	= bpf_prog_config_write,
};

static struct cmd_ext cmd_ext_bpf_prog = {
	.node		= &bpf_prog_node,
	.install	= cmd_ext_bpf_prog_install,
};

static void __attribute__((constructor))
fswan_bpf_prog_vty_init(void)
{
	cmd_ext_register(&cmd_ext_bpf_prog);
}
