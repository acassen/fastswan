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
#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <sys/stat.h>

/* defines */
#define PATH_MAX_LEN	256
#define DISK_ASYNC	0
#define DISK_SYNC	1

/* Map file */
struct map_file {
	char			path[PATH_MAX_LEN];
	struct stat		fstat;
	int			fd;
	void			*map;
};

/* Prototypes */
int disk_create(char *pathname, bool append);
void disk_close_fd(int *fd);
int disk_rm(const char *pathname);
int disk_mv(char *pathsrc, char *pathdst);
int disk_chown(const char *pathname, uid_t uid, gid_t gid);
int disk_map_open(struct map_file *m, size_t size);
int disk_map_close(struct map_file *m);
int disk_msync_offset(struct map_file *m, off_t offset,
		      size_t ssize, int flags);
int disk_map_resize(struct map_file *m, size_t new_size);
int disk_map_write(struct map_file *m, off_t offset,
		   const void *buf, size_t bsize);
int disk_map_write_sync(struct map_file *m, off_t offset, const void *buffer, size_t bsize);
int disk_map_write_async(struct map_file *m, off_t offset, const void *buffer, size_t bsize);
int disk_write(int fd, const void *buffer, int size);
int disk_read(int fd, void *buffer, int size);
