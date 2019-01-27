/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2019, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include "proc.h"

#include "tommyhash.h"
#include "filemon.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

static proc_t *proctab[UINT16_MAX + 1];
uint32_t procs; /* external access from procmap.c */

_Static_assert(sizeof(pid_t) == 4, "pid_t is 32bit");
#define hashpid(P) (uint16_t)tommy_inthash_u32((uint32_t)(P))

/*
 * file descriptor tracking
 */

fd_ctx_t *
proc_getfd(proc_t *proc, int fd) {
	if (fd < 0)
		return NULL;
	if (fd < (int)(sizeof(proc->fdlovect)/sizeof(proc->fdlovect[0])))
		return proc->fdlovect[fd];
	tommy_node *node = tommy_list_head(&proc->fdhilist);
	while (node) {
		fd_ctx_t *ctx = node->data;
		if (ctx->fd == fd)
			return ctx;
		node = node->next;
	}
	return NULL;
}

void
proc_setfd(proc_t *proc, fd_ctx_t *ctx) {
	if (ctx->fd < 0)
		return;
	if (ctx->fd < (int)(sizeof(proc->fdlovect)/sizeof(proc->fdlovect[0]))) {
		proc->fdlovect[ctx->fd] = ctx;
		tommy_list_insert_head(&proc->fdlolist, &ctx->node, ctx);
	} else {
		tommy_list_insert_head(&proc->fdhilist, &ctx->node, ctx);
	}
}

fd_ctx_t *
proc_closefd(proc_t *proc, int fd) {
	if (fd < 0)
		return NULL;
	if (fd < (int)(sizeof(proc->fdlovect)/sizeof(proc->fdlovect[0]))) {
		fd_ctx_t *ctx = proc->fdlovect[fd];
		proc->fdlovect[fd] = NULL;
		if (ctx)
			tommy_list_remove_existing(&proc->fdlolist, &ctx->node);
		return ctx;
	}
	tommy_node *node = tommy_list_head(&proc->fdhilist);
	while (node) {
		fd_ctx_t *ctx = node->data;
		if (ctx->fd == fd) {
			tommy_list_remove_existing(&proc->fdhilist, node);
			return ctx;
		}
		node = node->next;
	}
	return NULL;
}

void
proc_triggerfd(fd_ctx_t *ctx, struct timespec *tv) {
	if ((ctx->flags & FDFLAG_FILE) && ctx->fi.path) {
		assert(ctx->fi.path);
		filemon_touched(tv, &ctx->fi.subject, ctx->fi.path);
		ctx->fi.path = NULL;
	}
}

void
proc_freefd(fd_ctx_t *ctx) {
	if ((ctx->flags & FDFLAG_FILE) && ctx->fi.path) {
		free(ctx->fi.path);
		ctx->fi.path = NULL;
	}
	free(ctx);
}

/*
 * process tracking
 */

static proc_t *
proc_new(void) {
	proc_t *proc;

	proc = malloc(sizeof(proc_t));
	if (!proc)
		return NULL;
	bzero(proc, sizeof(proc_t));
	tommy_list_init(&proc->fdlolist);
	tommy_list_init(&proc->fdhilist);
	procs++;
	return proc;
}

/*
 * Timestamp tv is passed down from the event that caused the proc to be
 * evicted; used for events triggered by implicit closing of open files.
 * Subject and path are stored when setting the file descriptor.
 */
static void
proc_free(proc_t *proc, struct timespec *tv) {
	fd_ctx_t *ctx;

	assert(proc);
	while (!tommy_list_empty(&proc->fdlolist)) {
		ctx = tommy_list_remove_existing(&proc->fdlolist,
				tommy_list_head(&proc->fdlolist));
		if (tv)
			proc_triggerfd(ctx, tv);
		proc_freefd(ctx);
	}
	while (!tommy_list_empty(&proc->fdhilist)) {
		ctx = tommy_list_remove_existing(&proc->fdhilist,
				tommy_list_head(&proc->fdhilist));
		if (tv)
			proc_triggerfd(ctx, tv);
		proc_freefd(ctx);
	}
	if (proc->image_exec)
		image_exec_free(proc->image_exec);
	if (proc->cwd)
		free(proc->cwd);
	assert(procs > 0);
	procs--;
	free(proc);
}

/*
 * Precondition is that pid does not exist in proctab.
 *
 * Returned pointer points directly into proctab-internal storage.
 */
proc_t *
proctab_create(pid_t pid) {
	proc_t *proc;
	uint16_t h;

	h = hashpid(pid);
	proc = proctab[h];
	if (!proc) {
		proc = proc_new();
		if (proc == NULL)
			return NULL;
		proctab[h] = proc;
	} else {
		assert(proc->pid != pid);
		while (proc->next) {
			assert(proc->pid != pid);
			proc = proc->next;
		}
		proc->next = proc_new();
		if (proc->next == NULL)
			return NULL;
		proc = proc->next;
	}
	assert(proc);
	assert(!proc->next);
	proc->pid = pid;
	return proc;
}

/*
 * Returned pointer points directly into proctab-internal storage.
 */
proc_t *
proctab_find(pid_t pid) {
	proc_t *proc;

	proc = proctab[hashpid(pid)];
	if (proc) {
		if (proc->pid == pid)
			return proc;
		while ((proc = proc->next)) {
			if (proc->pid == pid)
				return proc;
		}
	}

	return NULL;
}

/*
 * Returned pointer points directly into proctab-internal storage.
 */
proc_t *
proctab_find_or_create(pid_t pid) {
	proc_t *proc;

	proc = proctab_find(pid);
	if (proc)
		return proc;

	return proctab_create(pid);
}

/*
 * Need to make sure to keep the proc_t accessible in proctab during
 * proc_free, because proc_free can trigger a launchd-add event which
 * in turn needs to loop up the proc to access the image_exec_t.
 */
void
proctab_remove(pid_t pid, struct timespec *tv) {
	proc_t *proc;
	uint16_t h;

	h = hashpid(pid);
	proc = proctab[h];
	if (proc) {
		/* pid is first in the list */
		if (proc->pid == pid) {
			proc_t *tmp = proc->next;
			proc_free(proc, tv);
			proctab[h] = tmp;
			return;
		}
		/* pid is not first in the list */
		while (proc->next) {
			if (proc->next->pid == pid) {
				proc_t *tmp = proc->next;
				proc_free(tmp, tv);
				proc->next = tmp->next;
				return;
			}
			proc = proc->next;
		}
	}
}

/*
 * Does not trigger any implicit close filemon events anymore.
 */
static void
proctab_flush(void) {
	proc_t *proc, *next;
	uint16_t h;

	for (size_t i = 0; i < (sizeof(proctab)/sizeof(proctab[0])); i++) {
		h = (uint16_t)i;
		proc = proctab[h];
		while (proc) {
			next = proc->next;
			proc_free(proc, NULL);
			proc = next;
		}
	}
}

void
proctab_init(void) {
	procs = 0;
	bzero(proctab, sizeof(proctab));
}

void
proctab_fini(void) {
	proctab_flush();
	assert(procs == 0);
}

