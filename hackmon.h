/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef HACKMON_H
#define HACKMON_H

#include "auevent.h"
#include "procmon.h"
#include "logevt.h"
#include "sys.h"
#include "config.h"
#include "attrib.h"

#include <sys/types.h>

typedef struct {
	uint64_t recvd;
	uint64_t procd;
	uint64_t ooms;
} hackmon_stat_t;

typedef struct {
	logevt_header_t hdr;
	audit_proc_t subject;
	audit_proc_t object;
	image_exec_t *subject_image_exec;
	image_exec_t *object_image_exec;
	const char *method; /* "ptrace" or "task_for_pid" */
} process_access_t;

void hackmon_taskforpid(struct timespec *, audit_proc_t *, audit_proc_t *,
                        pid_t) NONNULL(1,2);
void hackmon_ptrace(struct timespec *, audit_proc_t *, audit_proc_t *,
                    pid_t) NONNULL(1,2);

void hackmon_init(config_t *) NONNULL(1);
void hackmon_fini(void);
void hackmon_stats(hackmon_stat_t *) NONNULL(1);

#endif
