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

#ifndef _PKT_BUFFER_H
#define _PKT_BUFFER_H

/* defines */
#define DEFAULT_PKT_BUFFER_SIZE	4096

/* pkt related */
typedef struct _pkt_buffer {
	unsigned char		*head,
				*data;
	unsigned char		*end;
	unsigned char		*tail;
} pkt_buffer_t;

typedef struct _pkt {
	pkt_buffer_t		*pbuff;

	list_head_t		next;
} pkt_t;

typedef struct _mpkt {
	unsigned int		vlen;
	struct mmsghdr		*msgs;
	struct iovec		*iovecs;
	pkt_t			**pkt;
} mpkt_t;

typedef struct _pkt_queue {
	pthread_mutex_t		mutex;
	list_head_t		queue;
} pkt_queue_t;

static inline unsigned int pkt_buffer_len(pkt_buffer_t *b)
{
	return b->end - b->head;
}

static inline unsigned int pkt_buffer_size(pkt_buffer_t *b)
{
	return b->tail - b->head;
}

static inline unsigned int pkt_buffer_headroom(pkt_buffer_t *b)
{
	return b->data - b->head;
}

static inline unsigned int pkt_buffer_tailroom(pkt_buffer_t *b)
{
	return b->tail - b->end;
}

static inline unsigned int pkt_buffer_data_tailroom(pkt_buffer_t *b)
{
	return b->end - b->data;
}

static inline unsigned char *pkt_buffer_end(pkt_buffer_t *b)
{
	return b->end;
}

static inline void pkt_buffer_reset(pkt_buffer_t *b)
{
	b->data = b->end = b->head;
}

static inline void pkt_buffer_reset_data(pkt_buffer_t *b)
{
	b->data = b->head;
}

static inline void pkt_buffer_set_end_pointer(pkt_buffer_t *b, unsigned int offset)
{
	b->end = b->head + offset;
}

static inline void pkt_buffer_set_data_pointer(pkt_buffer_t *b, unsigned int offset)
{
	b->data = b->head + offset;
}

static inline void pkt_buffer_put_data(pkt_buffer_t *b, unsigned int offset)
{
	b->data += offset;
}

static inline void pkt_buffer_put_end(pkt_buffer_t *b, unsigned int offset)
{
	b->end += offset;
}

/* Prototypes */
extern ssize_t pkt_send(int fd, pkt_queue_t *, pkt_t *);
extern ssize_t pkt_recv(int fd, pkt_t *);
extern int mpkt_recv(int, mpkt_t *);
extern void pkt_queue_run(pkt_queue_t *, int (*run) (pkt_t *, void *), void *);
extern pkt_t *pkt_queue_get(pkt_queue_t *);
extern int __pkt_queue_put(pkt_queue_t *, pkt_t *);
extern int pkt_queue_put(pkt_queue_t *, pkt_t *);
extern int mpkt_init(mpkt_t *, unsigned int);
extern void mpkt_process(mpkt_t *, unsigned int, void (*process) (pkt_t *, void *), void *);
extern void mpkt_destroy(mpkt_t *);
extern void mpkt_reset(mpkt_t *);
extern int __pkt_queue_mget(pkt_queue_t *, mpkt_t *);
extern int pkt_queue_mget(pkt_queue_t *, mpkt_t *);
extern int __pkt_queue_mput(pkt_queue_t *, mpkt_t *);
extern int pkt_queue_mput(pkt_queue_t *, mpkt_t *);
extern int pkt_queue_init(pkt_queue_t *);
extern int pkt_queue_destroy(pkt_queue_t *);
extern ssize_t pkt_buffer_send(int, pkt_buffer_t *, struct sockaddr_storage *);
extern int pkt_buffer_put_zero(pkt_buffer_t *, unsigned int);
extern int pkt_buffer_pad(pkt_buffer_t *, unsigned int);
extern pkt_buffer_t *pkt_buffer_alloc(unsigned int);
extern void pkt_buffer_free(pkt_buffer_t *);

#endif
