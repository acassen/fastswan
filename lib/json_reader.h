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

#ifndef _JSON_READER_H_
#define _JSON_READER_H_

#include <stdbool.h>
#include <stddef.h>

typedef enum {
        JSON_NULL = 0,
        JSON_BOOL,
        JSON_STRING,
        JSON_NUMBER,
        JSON_ARRAY,
        JSON_OBJECT,
} json_tag_t;

typedef struct _json_node {
	struct _json_node	*parent, *prev, *next;
	char			*key;
	json_tag_t		tag;
	union {
		bool		bool_value;	/* JSON_BOOL */
		char		*str_value;	/* JSON_STRING */
		double		number_value;	/* JSON_NUMBER */
		struct {			/* JSON_ARRAY|JSON_OBJECT */
			struct	_json_node *head, *tail;
		} child;
	};
} json_node_t;


/* Walk the line */
extern json_node_t *json_find_member_boolvalue(json_node_t *, const char *, bool *);
extern json_node_t *json_find_member_strvalue(json_node_t *, const char *, char **);
extern json_node_t *json_find_member_numbervalue(json_node_t *, const char *, double *);
extern json_node_t *json_find_member_doublevalue(json_node_t *, const char *, double *);
extern json_node_t *json_find_member_intvalue(json_node_t *, const char *, int *);
extern json_node_t *json_find_member(json_node_t *, const char *);
extern json_node_t *json_first_child(const json_node_t *);
#define json_for_each_node(pos, head)		\
	for (pos = json_first_child(head);	\
		pos != NULL;			\
		pos = pos->next)

#define json_for_each_node_safe(pos, n, head)			\
	for (pos = json_first_child(head), n = pos->next;	\
		pos != NULL && (n = pos->next);			\
		pos = n, n = (pos->next) ? pos->next : NULL)


/* Prototypes */
extern json_node_t *json_decode(const char *);
extern void json_dump(json_node_t *);
extern void json_destroy(json_node_t *);

#endif
