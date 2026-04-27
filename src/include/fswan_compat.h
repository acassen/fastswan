/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Compatibility shim. gtp-guard's lib/ dropped the historical typedefs
 * (list_head_t, vty_t, thread_t, thread_ref_t, thread_master_t) in favour of
 * plain struct names. fastswan's src/ still uses the typedefs; declare them
 * here so the resynced lib/ headers match gtp-guard byte-for-byte.
 *
 * Copyright (C) 2025-2026 Alexandre Cassen, <acassen@gmail.com>
 */
#pragma once

#include "list_head.h"
#include "vty.h"
#include "thread.h"
#include "command.h"
#include "inet_utils.h"

typedef struct list_head	list_head_t;
typedef struct vty		vty_t;
typedef struct thread		thread_t;
typedef struct thread		*thread_ref_t;
typedef struct thread_master	thread_master_t;
typedef struct cmd_node		cmd_node_t;

/* fastswan historically used BPF_NODE; gtp-guard renamed it to BPF_PROG_NODE. */
#define BPF_NODE BPF_PROG_NODE

/* gtp-guard renamed thread_cancel() to thread_del(). */
#define thread_cancel(t) thread_del(t)
