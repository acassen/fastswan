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

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <termios.h>
#include <arpa/telnet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "thread.h"
#include "fswan_vty_shell.h"

enum telnet_state {
	TEL_NORMAL,
	TEL_IAC,
	TEL_OPT,
	TEL_SB,
	TEL_SB_IAC,
};

struct fswan_vtysh {
	int sock_fd;
	struct termios orig;
	struct thread_master *master;
	struct thread *t_stdin;
	struct thread *t_sock;
	enum telnet_state tel_state;
	unsigned char tel_cmd;
};
static struct fswan_vtysh fswan_vtysh_data;

static void fswan_vtysh_stdin_read(struct thread *t);
static void fswan_vtysh_sock_read(struct thread *t);


static ssize_t
fswan_vtysh_send_naws(int fd)
{
	/* struct winsize layout: ws_row, ws_col, ws_xpixel, ws_ypixel */
	unsigned short winsz[4] = {24, 80, 0, 0};
	unsigned char buf[12];
	int len = 0;

	ioctl(STDIN_FILENO, TIOCGWINSZ, winsz);

	buf[len++] = IAC;
	buf[len++] = WILL;
	buf[len++] = TELOPT_NAWS;
	buf[len++] = IAC;
	buf[len++] = SB;
	buf[len++] = TELOPT_NAWS;
	buf[len++] = (winsz[1] >> 8) & 0xff;	/* cols high */
	buf[len++] = winsz[1] & 0xff;		/* cols low */
	buf[len++] = (winsz[0] >> 8) & 0xff;	/* rows high */
	buf[len++] = winsz[0] & 0xff;		/* rows low */
	buf[len++] = IAC;
	buf[len++] = SE;
	return write(fd, buf, len);
}

static void
fswan_vtysh_sigwinch(__attribute__((unused)) int sig)
{
	fswan_vtysh_send_naws(fswan_vtysh_data.sock_fd);
}

static void
fswan_vtysh_signal_handler(__attribute__((unused)) int sig)
{
	tcsetattr(STDIN_FILENO, TCSANOW, &fswan_vtysh_data.orig);
	_exit(1);
}

static void
fswan_vtysh_close(struct fswan_vtysh *ctx)
{
	tcsetattr(STDIN_FILENO, TCSANOW, &ctx->orig);
	close(ctx->sock_fd);
	thread_add_terminate_event(ctx->master);
}


/*
 *	Strip IAC sequences from telnet server output.
 */
static int
fswan_vtysh_telnet_filter(struct fswan_vtysh *ctx, const unsigned char *in,
			  int inlen, unsigned char *out, int outsize)
{
	int i, pos = 0;

	for (i = 0; i < inlen && pos < outsize; i++) {
		unsigned char c = in[i];

		switch (ctx->tel_state) {
		case TEL_NORMAL:
			if (c == IAC)
				ctx->tel_state = TEL_IAC;
			else
				out[pos++] = c;
			break;
		case TEL_IAC:
			switch (c) {
			case IAC:
				/* Escaped 0xFF */
				out[pos++] = IAC;
				ctx->tel_state = TEL_NORMAL;
				break;
			case SB:
				ctx->tel_state = TEL_SB;
				break;
			case WILL:
			case WONT:
			case DO:
			case DONT:
				ctx->tel_cmd = c;
				ctx->tel_state = TEL_OPT;
				break;
			default:
				/* Other 2-byte command */
				ctx->tel_state = TEL_NORMAL;
				break;
			}
			break;
		case TEL_OPT:
			if (ctx->tel_cmd == DO && c == TELOPT_NAWS)
				fswan_vtysh_send_naws(ctx->sock_fd);
			ctx->tel_state = TEL_NORMAL;
			break;
		case TEL_SB:
			if (c == IAC)
				ctx->tel_state = TEL_SB_IAC;
			break;
		case TEL_SB_IAC:
			if (c == SE)
				ctx->tel_state = TEL_NORMAL;
			else
				ctx->tel_state = TEL_SB;
			break;
		}
	}

	return pos;
}


/*
 *	stdin to socket relay
 */
static void
fswan_vtysh_stdin_read(struct thread *t)
{
	struct fswan_vtysh *ctx = THREAD_ARG(t);
	char buf[512];
	ssize_t n;

	n = read(STDIN_FILENO, buf, sizeof(buf));
	if (n <= 0)
		goto close;

	if (write(ctx->sock_fd, buf, n) != n)
		goto close;

	ctx->t_stdin = thread_add_read(ctx->master, fswan_vtysh_stdin_read, ctx,
				       STDIN_FILENO, TIMER_NEVER, 0);
	return;

close:
	ctx->t_stdin = NULL;
	fswan_vtysh_close(ctx);
	return;

}


/*
 *	socket to stdout relay
 */
static void
fswan_vtysh_sock_read(struct thread *t)
{
	struct fswan_vtysh *ctx = THREAD_ARG(t);
	unsigned char buf[512];
	unsigned char filtered[512];
	ssize_t n;
	int flen;

	n = read(ctx->sock_fd, buf, sizeof(buf));
	if (n <= 0)
		goto close;

	flen = fswan_vtysh_telnet_filter(ctx, buf, n, filtered, sizeof(filtered));
	if (flen > 0 && write(STDOUT_FILENO, filtered, flen) != flen)
		goto close;

	ctx->t_sock = thread_add_read(ctx->master, fswan_vtysh_sock_read, ctx,
				      ctx->sock_fd, TIMER_NEVER, 0);
	return;

close:
	ctx->t_sock = NULL;
	fswan_vtysh_close(ctx);
	return;
}


/*
 *	Connect to AF_UNIX vty socket and act as a telnet client
 */
int
fswan_vtysh(const char *path)
{
	struct fswan_vtysh *ctx = &fswan_vtysh_data;
	struct sockaddr_un addr;
	struct termios raw;
	int fd;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		fprintf(stderr, "Error creating socket (%m)\n");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "Error connectinf to %s (%m)\n", path);
		goto err;
	}

	memset(ctx, 0, sizeof(*ctx));
	ctx->sock_fd = fd;

	if (tcgetattr(STDIN_FILENO, &ctx->orig) < 0) {
		fprintf(stderr, "tcgetattr error (%m)\n");
		goto err;
	}

	ctx->master = thread_make_master(true);
	if (!ctx->master) {
		fprintf(stderr, "Failed to create scheduler\n");
		goto err;
	}

	/* Restore terminal on fatal signals */
	signal(SIGINT, fswan_vtysh_signal_handler);
	signal(SIGTERM, fswan_vtysh_signal_handler);
	signal(SIGQUIT, fswan_vtysh_signal_handler);
	signal(SIGTSTP, SIG_IGN);
	signal(SIGHUP, fswan_vtysh_signal_handler);
	signal(SIGWINCH, fswan_vtysh_sigwinch);

	raw = ctx->orig;
	cfmakeraw(&raw);
	tcsetattr(STDIN_FILENO, TCSANOW, &raw);

	ctx->t_stdin = thread_add_read(ctx->master, fswan_vtysh_stdin_read, ctx,
				       STDIN_FILENO, TIMER_NEVER, 0);
	ctx->t_sock = thread_add_read(ctx->master, fswan_vtysh_sock_read, ctx,
				      ctx->sock_fd, TIMER_NEVER, 0);

	launch_thread_scheduler(ctx->master);

	thread_destroy_master(ctx->master);
	return 0;

err:
	close(fd);
	return -1;
}
