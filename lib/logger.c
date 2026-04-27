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

#include <stdlib.h>
#include <syslog.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>

/* Boolean flag - send messages to console instead of syslog */
static bool log_console = false;

void
enable_console_log(void)
{
	log_console = true;
}

void
log_message_va(const int priority, const char *fmt, va_list args)
{
	char buf[512];
	int n;

	if (log_console) {
		va_list args_cp;
		char *p = NULL;

		va_copy(args_cp, args);
		n = vsnprintf(buf, sizeof (buf), fmt, args);

		/* output was truncated, we want full output on stderr */
		if (n >= sizeof (buf)) {
			p = malloc(n + 2);
			if (!p)
				return;
			n = vsnprintf(p, n + 1, fmt, args_cp);
		} else {
			p = buf;
		}
		/* add trailing '\n' if there is none */
		if (n > 0 && p[n - 1] == '\n')
			p[n - 1] = 0;
		fprintf(stderr, "%s\n", p);
		if (p != buf)
			free(p);
	} else {
		vsnprintf(buf, sizeof (buf), fmt, args);
		syslog(priority, "%s", buf);
	}
}

void
log_message(const int priority, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	log_message_va(priority, fmt, args);
	va_end(args);
}

void
conf_write(FILE *fp, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	if (fp) {
		vfprintf(fp, fmt, args);
		fprintf(fp, "\n");
	} else
		log_message_va(LOG_INFO, fmt, args);

	va_end(args);
}
