/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef KQUEUE_H
#define KQUEUE_H

#include "tommylist.h"
#include "attrib.h"

#include <sys/types.h>
#include <stdio.h>
#include <stdbool.h>
#include <signal.h>

typedef int (*kevent_fd_read_func_t)(int, void *);
typedef bool (*kevent_fd_prio_func_t)(int, void *);
typedef int (*kevent_signal_func_t)(int, void *);
typedef int (*kevent_timer_func_t)(int, void *);

typedef struct kevent_ctx {
	kevent_fd_read_func_t fd_read;
	kevent_fd_prio_func_t fd_prio;
	kevent_signal_func_t signal;
	kevent_timer_func_t timer;
	void *udata;
	tommy_node node;
} kevent_ctx_t;

#define TOMMY_NODE_INIT {NULL, NULL, NULL, 0}

#define KEVENT_CTX_SIGNAL(S,U)         {NULL,NULL,(S),NULL,(U),TOMMY_NODE_INIT}
#define KEVENT_CTX_FD_READ(R,U)        {(R),NULL,NULL,NULL,(U),TOMMY_NODE_INIT}
#define KEVENT_CTX_FD_READ_PRIO(R,P,U) {(R),(P),NULL,NULL,(U),TOMMY_NODE_INIT}
#define KEVENT_CTX_TIMER(T,U)          {NULL,NULL,NULL,(T),(U),TOMMY_NODE_INIT}

int kqueue_init(void) WUNRES;
void kqueue_fini(void);
int kqueue_dispatch(void) WUNRES;
int kqueue_add_fd_read(int, kevent_ctx_t *) NONNULL(2) WUNRES;
int kqueue_add_signal(int, kevent_ctx_t *) NONNULL(2) WUNRES;
int kqueue_add_timer(int, int, kevent_ctx_t *) NONNULL(3) WUNRES;

#endif
