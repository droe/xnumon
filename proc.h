/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef PROC_H
#define PROC_H

#include "procmon.h" /* image_exec_t */

#include "tommylist.h"

#include <sys/types.h>

typedef struct {
	tommy_node node;

	int fd;

	/* socket */
	int proto;
	ipaddr_t addr;
	uint16_t port;
} fd_ctx_t;

typedef struct proc {
	/* fork meta-data at time of fork */
	pid_t pid;
	struct timespec fork_tv;

	/* image of last exec */
	image_exec_t *image_exec;

	/* current working directory, tracked via chdir/fchdir */
	char *cwd;

	/* hashtable bucket linkage */
	struct proc *next;

	/* open file descriptors */
	tommy_list fdlist;
} proc_t;

extern uint32_t procs;

void proctab_init(void);
void proctab_fini(void);
proc_t * proctab_create(pid_t);
proc_t * proctab_find_or_create(pid_t);
proc_t * proctab_find(pid_t);
void proctab_remove(pid_t);

tommy_node * proc_find_fd(proc_t *, int) NONNULL(1) WUNRES;

#endif

