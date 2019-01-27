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

#include "tommylist.h"

#include <sys/types.h>

typedef struct {
	tommy_node node;

	int fd;
	int flags;
#define FDFLAG_SOCKET   1
#define FDFLAG_FILE     2
#define FDFLAG_CLOEXEC  4 /* unused */

	union {
		struct {
			int proto;
			ipaddr_t addr;
			uint16_t port;
		} so;
		struct {
			audit_proc_t subject;
			char *path;
		} fi;
	};
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

	/*
	 * Open file descriptors smaller than default RLIMIT_NOFILE stored in
	 * pointer array in addition to a list to allow O(1) access time but
	 * still quick iteration on exit with only few descriptors.  This
	 * yields good access complexity except for large network servers with
	 * thousands of open sockets. FIXME look into alternatives
	 */
	fd_ctx_t *fdlovect[256];
	tommy_list fdlolist;
	tommy_list fdhilist;
} proc_t;

extern uint32_t procs;

void proctab_init(void);
void proctab_fini(void);
proc_t * proctab_create(pid_t);
proc_t * proctab_find_or_create(pid_t);
proc_t * proctab_find(pid_t);
void proctab_remove(pid_t, struct timespec *);

fd_ctx_t * proc_getfd(proc_t *, int) NONNULL(1) WUNRES;
fd_ctx_t * proc_closefd(proc_t *, int) NONNULL(1) WUNRES;
void proc_setfd(proc_t *, fd_ctx_t *) NONNULL(1,2);
void proc_triggerfd(fd_ctx_t *ctx, struct timespec *tv) NONNULL(1,2);
void proc_freefd(fd_ctx_t *) NONNULL(1);

#endif

