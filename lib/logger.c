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

#include <syslog.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>

/* Boolean flag - send messages to console as well as syslog */
static bool log_console = false;

void
enable_console_log(void)
{
	log_console = true;
}

void
log_message(const int facility, const char *format, ...)
{
	va_list args;
	char buf[256];

	va_start(args, format);
	vsnprintf(buf, sizeof(buf), format, args);
	va_end(args);

	if (log_console) {
		fprintf(stderr, "%s\n", buf);
	}

	syslog(facility, "%s", buf);
}

void
conf_write(FILE *fp, const char *format, ...)
{
        va_list args;

        va_start(args, format);
        if (fp) {
                vfprintf(fp, format, args);
                fprintf(fp, "\n");
        } else
                log_message(LOG_INFO, format, args);

        va_end(args);
}
