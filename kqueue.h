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
typedef int (*kevent_signal_func_t)(int, void *);
typedef int (*kevent_timer_func_t)(int, void *);

typedef struct {
	kevent_fd_read_func_t fd_read;
	kevent_signal_func_t signal;
	kevent_timer_func_t timer;
	void *udata;
} kevent_ctx_t;

#define KEVENT_CTX_SIGNAL(SF,UD)            {NULL, (SF), NULL, (UD)}
#define KEVENT_CTX_FD_READ(RF,UD)           {(RF), NULL, NULL, (UD)}
#define KEVENT_CTX_TIMER(TF,UD)             {NULL, NULL, (TF), (UD)}

typedef struct {
	int fd;
	struct kevent *ke;
	size_t nke;
} kqueue_t;

kqueue_t * kqueue_new(void) MALLOC;
void kqueue_free(kqueue_t *) NONNULL(1);
int kqueue_dispatch(kqueue_t *) NONNULL(1) WUNRES;
int kqueue_add_fd_read(kqueue_t *, int, kevent_ctx_t *) NONNULL(1,3) WUNRES;
int kqueue_add_signal(kqueue_t *, int, kevent_ctx_t *) NONNULL(1,3) WUNRES;
int kqueue_add_timer(kqueue_t *, int, int, kevent_ctx_t *) NONNULL(1,4) WUNRES;

#endif
