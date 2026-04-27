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

#include <stdbool.h>

enum json_tag {
        JSON_NULL = 0,
        JSON_BOOL,
        JSON_STRING,
        JSON_NUMBER,
        JSON_ARRAY,
        JSON_OBJECT,
};

struct json_node {
	struct json_node	*parent, *prev, *next;
	char			*key;
	enum json_tag		tag;
	union {
		bool		bool_value;	/* JSON_BOOL */
		char		*str_value;	/* JSON_STRING */
		double		number_value;	/* JSON_NUMBER */
		struct {			/* JSON_ARRAY|JSON_OBJECT */
			struct	json_node *head, *tail;
		} child;
	};
};


/* Walk the line */
struct json_node *json_find_member_boolvalue(struct json_node *node, const char *name,
					     bool *value);
struct json_node *json_find_member_strvalue(struct json_node *node, const char *name,
					    char **value);
struct json_node *json_find_member_numbervalue(struct json_node *node, const char *name,
					       double *value);
struct json_node *json_find_member_doublevalue(struct json_node *node, const char *name,
					       double *value);
struct json_node *json_find_member_intvalue(struct json_node *node, const char *name,
					    int *value);
struct json_node *json_find_member(struct json_node *node, const char *name);
struct json_node *json_first_child(const struct json_node *);
#define json_for_each_node(pos, head)		\
	for (pos = json_first_child(head);	\
		pos != NULL;			\
		pos = pos->next)

#define json_for_each_node_safe(pos, n, head)			\
	for (pos = json_first_child(head), n = pos->next;	\
		pos != NULL && (n = pos->next);			\
		pos = n, n = (pos->next) ? pos->next : NULL)


/* Prototypes */
struct json_node *json_decode(const char *str);
void json_dump(struct json_node *node);
void json_destroy(struct json_node *node);
