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

#include "pidfile.h"

/* Create the runnnig daemon pidfile */
int
pidfile_write(char *pid_file, int pid)
{
	FILE *pidfile = fopen(pid_file, "w");

	if (!pidfile) {
		syslog(LOG_INFO, "pidfile_write : Can not open %s pidfile",
		       pid_file);
		return 0;
	}
	fprintf(pidfile, "%d\n", pid);
	fclose(pidfile);
	return 1;
}

/* Remove the running daemon pidfile */
void
pidfile_rm(char *pid_file)
{
	unlink(pid_file);
}

/* return the daemon running state */
int
process_running(char *pid_file)
{
	FILE *pidfile = fopen(pid_file, "r");
	pid_t pid;
	int ret;

	/* No pidfile */
	if (!pidfile)
		return 0;

	ret = fscanf(pidfile, "%d", &pid);
	if (ret == EOF)
		syslog(LOG_INFO, "Error reading pid file %s (%d)", pid_file, ferror(pidfile));
	fclose(pidfile);

	/* If no process is attached to pidfile, remove it */
	if (kill(pid, 0)) {
		syslog(LOG_INFO, "Remove a zombie pid file %s", pid_file);
		pidfile_rm(pid_file);
		return 0;
	}

	return 1;
}
