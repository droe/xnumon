/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include "proc.h"

#include "tommyhash.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

static proc_t *proctab[UINT16_MAX + 1];
uint32_t procs; /* external access from procmap.c */

_Static_assert(sizeof(pid_t) == 4, "pid_t is 32bit");
#define hashpid(P) (uint16_t)tommy_inthash_u32((uint32_t)(P))

static proc_t *
proc_new(void) {
	proc_t *proc;

	proc = malloc(sizeof(proc_t));
	if (!proc)
		return NULL;
	bzero(proc, sizeof(proc_t));
	tommy_list_init(&proc->fdlist);
	procs++;
	return proc;
}

static void
proc_free(proc_t *proc) {
	assert(proc);
	while (!tommy_list_empty(&proc->fdlist)) {
		void *ctx;
		ctx = tommy_list_remove_existing(&proc->fdlist,
				tommy_list_head(&proc->fdlist));
		free(ctx);
	}
	if (proc->image_exec)
		image_exec_free(proc->image_exec);
	if (proc->cwd)
		free(proc->cwd);
	assert(procs > 0);
	procs--;
	free(proc);
}

tommy_node *
proc_find_fd(proc_t *proc, int fd) {
	tommy_node *node = tommy_list_head(&proc->fdlist);
	while (node) {
		fd_ctx_t *ctx = node->data;
		if (ctx->fd == fd) /* XXX WHY CRASH HERE??? */
			return node;
		node = node->next;
	}
	return NULL;
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

void
proctab_remove(pid_t pid) {
	proc_t *proc;
	uint16_t h;

	h = hashpid(pid);
	proc = proctab[h];
	if (proc) {
		/* pid is first in the list */
		if (proc->pid == pid) {
			proctab[h] = proc->next;
			proc_free(proc);
			return;
		}
		/* pid is not first in the list */
		while (proc->next) {
			if (proc->next->pid == pid) {
				proc_t *tmp = proc->next;
				proc->next = proc->next->next;
				proc_free(tmp);
				return;
			}
			proc = proc->next;
		}
	}
}

static void
proctab_flush(void) {
	proc_t *proc, *next;
	uint16_t h;

	for (size_t i = 0; i < (sizeof(proctab)/sizeof(proctab[0])); i++) {
		h = (uint16_t)i;
		proc = proctab[h];
		while (proc) {
			next = proc->next;
			proc_free(proc);
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

