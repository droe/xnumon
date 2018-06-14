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

static int kqfd = -1;
static struct kevent *ke;
static int nke;

static int
ke_enlarge(void) {
	nke++;
	ke = realloc(ke, nke * sizeof(struct kevent));
	if (!ke)
		return -1;
	return 0;
}

int
kqueue_init(void) {
	kqfd = kqueue();
	if (kqfd == -1)
		return -1;
	nke = 0;
	ke = NULL;
	return 0;
}

void
kqueue_fini(void) {
	if (kqfd != -1)
		close(kqfd);
	if (ke) {
		free(ke);
		ke = NULL;
	}
}

int
kqueue_dispatch(void) {
	int nev, i, rv;
	kevent_ctx_t *ctx;

	if (!ke)
		return -1;

retry:
	nev = kevent(kqfd, NULL, 0, ke, nke, NULL);
	if (nev == -1) {
		if (errno == EINTR)
			goto retry;
		fprintf(stderr, "kevent() failed: %s (%i)\n",
		        strerror(errno), errno);
		return -1;
	}

	/* process signals */
	for (i = 0; i < nev; i++) {
		if (ke[i].filter != EVFILT_SIGNAL)
			continue;
		ctx = (kevent_ctx_t *)ke[i].udata;
		assert(ctx);
		assert(ctx->signal);
		if (ctx->signal((int)ke[i].ident, ctx->udata) == -1)
			return -1;
	}

	/* process timers */
	for (i = 0; i < nev; i++) {
		if (ke[i].filter != EVFILT_TIMER)
			continue;
		ctx = (kevent_ctx_t *)ke[i].udata;
		assert(ctx);
		assert(ctx->timer);
		if (ctx->timer((int)ke[i].ident, ctx->udata) == -1)
			return -1;
	}

	/* process prioritiy file descriptors */
	for (i = 0; i < nev; i++) {
		if (ke[i].filter != EVFILT_READ)
			continue;
		ctx = (kevent_ctx_t *)ke[i].udata;
		assert(ctx);
		if (!ctx->fd_prio)
			continue;
		rv = ctx->fd_prio((int)ke[i].ident, ctx->udata);
		if (rv == -1)
			return -1;
		if (rv == 0)
			continue;
		assert(ctx->fd_read);
		if (ctx->fd_read((int)ke[i].ident, ctx->udata) == -1)
			return -1;
		return 0; /* drain */
	}

	/* process file descriptors without priority function */
	for (i = 0; i < nev; i++) {
		if (ke[i].filter != EVFILT_READ)
			continue;
		ctx = (kevent_ctx_t *)ke[i].udata;
		assert(ctx);
		if (ctx->fd_prio)
			continue;
		assert(ctx->fd_read);
		if (ctx->fd_read((int)ke[i].ident, ctx->udata) == -1)
			return -1;
		return 0; /* drain */
	}

	/* process file descriptors with priority function, but no priority */
	for (i = 0; i < nev; i++) {
		if (ke[i].filter != EVFILT_READ)
			continue;
		ctx = (kevent_ctx_t *)ke[i].udata;
		assert(ctx);
		if (!ctx->fd_prio)
			continue;
		assert(ctx->fd_read);
		if (ctx->fd_read((int)ke[i].ident, ctx->udata) == -1)
			return -1;
		return 0; /* drain */
	}

	return 0;
}

int
kqueue_add_fd_read(int fd, kevent_ctx_t *ctx) {
	struct kevent ke;

	if (ke_enlarge() == -1)
		return -1;
	EV_SET(&ke, fd, EVFILT_READ, EV_ADD, NOTE_LOWAT, 1, ctx);
	return kevent(kqfd, &ke, 1, NULL, 0, NULL);
}

int
kqueue_add_signal(int sig, kevent_ctx_t *ctx) {
	struct kevent ke;

	if (ke_enlarge() == -1)
		return -1;
	signal(sig, SIG_IGN);
	EV_SET(&ke, sig, EVFILT_SIGNAL, EV_ADD, 0, 0, ctx);
	return kevent(kqfd, &ke, 1, NULL, 0, NULL);
}

int
kqueue_add_timer(int ident, int secs, kevent_ctx_t *ctx) {
	struct kevent ke;

	if (ke_enlarge() == -1)
		return -1;
	EV_SET(&ke, ident, EVFILT_TIMER, EV_ADD, NOTE_SECONDS, secs, ctx);
	return kevent(kqfd, &ke, 1, NULL, 0, NULL);
}

