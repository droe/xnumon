/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include "kqueue.h"

#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

/*
 * Note that we add /dev/auditpipe and /dev/xnumon file descriptors to a
 * kqueue.  According to the manual page history, this is only supported
 * starting with XNU 3247.1.106 (10.11 El Capitan); sure enough it fails on
 * 10.8 Mountain Lion.  In order to support older kernels, we would have to
 * resort to using select() or poll() over the two cdev file descriptors and
 * the kqueue fd for signals and timers.  For now, only support 10.11+.
 */

static int
kqueue_enlarge(kqueue_t *kq) {
	kq->nke++;
	kq->ke = realloc(kq->ke, kq->nke * sizeof(struct kevent));
	if (!kq->ke)
		return -1;
	return 0;
}

kqueue_t *
kqueue_new(void) {
	kqueue_t *kq;

	kq = malloc(sizeof(kqueue_t));
	if (!kq)
		return NULL;
	bzero(kq, sizeof(kqueue_t));
	kq->fd = kqueue();
	if (kq->fd == -1) {
		free(kq);
		return NULL;
	}
	return kq;
}

void
kqueue_free(kqueue_t *kq) {
	if (kq->fd != -1)
		close(kq->fd);
	if (kq->ke)
		free(kq->ke);
	free(kq);
}

int
kqueue_dispatch(kqueue_t *kq) {
	kevent_ctx_t *ctx;
	int nev;
	struct timespec timeout;

	if (!kq->ke)
		return -1;

	bzero(&timeout, sizeof(struct timespec));
	timeout.tv_sec = 1;

retry:
	nev = kevent(kq->fd, NULL, 0, kq->ke, kq->nke, &timeout);
	if (nev == 0)
		return 0;
	if (nev == -1) {
		if (errno == EINTR)
			goto retry;
		fprintf(stderr, "kevent() failed: %s (%i)\n",
		        strerror(errno), errno);
		return -1;
	}

	/* process signals */
	for (size_t i = 0; i < (size_t)nev; i++) {
		if (kq->ke[i].filter != EVFILT_SIGNAL)
			continue;
		ctx = (kevent_ctx_t *)kq->ke[i].udata;
		assert(ctx);
		assert(ctx->signal);
		if (ctx->signal((int)kq->ke[i].ident, ctx->udata) == -1)
			return -1;
	}

	/* process timers */
	for (size_t i = 0; i < (size_t)nev; i++) {
		if (kq->ke[i].filter != EVFILT_TIMER)
			continue;
		ctx = (kevent_ctx_t *)kq->ke[i].udata;
		assert(ctx);
		assert(ctx->timer);
		if (ctx->timer((int)kq->ke[i].ident, ctx->udata) == -1)
			return -1;
	}

	/* process file descriptors */
	for (size_t i = 0; i < (size_t)nev; i++) {
		if (kq->ke[i].filter != EVFILT_READ)
			continue;
		ctx = (kevent_ctx_t *)kq->ke[i].udata;
		assert(ctx);
		assert(ctx->fd_read);
		if (ctx->fd_read((int)kq->ke[i].ident, ctx->udata) == -1)
			return -1;
	}

	return 0;
}

int
kqueue_add_fd_read(kqueue_t *kq, int fd, kevent_ctx_t *ctx) {
	struct kevent ke;

	if (kqueue_enlarge(kq) == -1)
		return -1;
	EV_SET(&ke, fd, EVFILT_READ, EV_ADD, NOTE_LOWAT, 1, ctx);
	return kevent(kq->fd, &ke, 1, NULL, 0, NULL);
}

int
kqueue_add_signal(kqueue_t *kq, int sig, kevent_ctx_t *ctx) {
	struct kevent ke;

	if (kqueue_enlarge(kq) == -1)
		return -1;
	signal(sig, SIG_IGN);
	EV_SET(&ke, sig, EVFILT_SIGNAL, EV_ADD, 0, 0, ctx);
	return kevent(kq->fd, &ke, 1, NULL, 0, NULL);
}

int
kqueue_add_timer(kqueue_t *kq, int ident, int secs, kevent_ctx_t *ctx) {
	struct kevent ke;

	if (kqueue_enlarge(kq) == -1)
		return -1;
	EV_SET(&ke, ident, EVFILT_TIMER, EV_ADD, NOTE_SECONDS, secs, ctx);
	return kevent(kq->fd, &ke, 1, NULL, 0, NULL);
}

