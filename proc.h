/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2019, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef PROC_H
#define PROC_H

#include "procmon.h" /* image_exec_t */

#include <sys/types.h>

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
} proc_t;

extern uint32_t procs;

void proctab_init(void);
void proctab_fini(void);
proc_t * proctab_create(pid_t);
proc_t * proctab_find_or_create(pid_t);
proc_t * proctab_find(pid_t);
void proctab_remove(pid_t);

#endif

