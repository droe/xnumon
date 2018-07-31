/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef LOGEVT_H
#define LOGEVT_H

#include "logfmt.h"
#include "config.h"
#include "attrib.h"

#include "tommylist.h"

#include <time.h>
#include <stdint.h>
#include <stdio.h>

/*
 * LOGEVT_VERSION must be incremented whenever the semantics or syntax of the
 * log events change in any of the log formats.  Adding information without
 * breaking backwards compatibility also counts as a change.  This is to
 * facilitate compatibility management of tooling and data processing that
 * depends on specific data to be presented in specific ways.  The config
 * dump in eventcode 0 is not considered part of the log event schema.
 *
 * LOGEVT_VERSION is only incremented at most once per xnumon release, which
 * means that changes may happen between different commits during development
 * without increasing LOGEVT_VERSION every time.
 */
#define LOGEVT_VERSION  7

/*
 * This must be the very first element of all log event data structs passed
 * to work_submit and log_submit.
 */
typedef int (*logevt_work_func_t)(void *);
typedef void (*logevt_free_func_t)(void *);
typedef struct {
	uint64_t code;
#define LOGEVT_XNUMON_OPS       0       /* xnumon_ops_t */
#define LOGEVT_XNUMON_STATS     1       /* evtloop_stat_t */
#define LOGEVT_IMAGE_EXEC       2       /* image_exec_t */
#define LOGEVT_PROCESS_ACCESS   3       /* process_access_t */
#define LOGEVT_LAUNCHD_ADD      4       /* launchd_add_t */
#define LOGEVT_SIZE             5
	struct timespec tv;
	logevt_work_func_t le_work;
	logevt_free_func_t le_free;
	tommy_node node;
} logevt_header_t;

#define LOGEVT_FLAG(E) (1 << (E))
#define LOGEVT_WANT(F,E) ((E) & (F))
#define LOGEVT_HACKMON LOGEVT_FLAG(LOGEVT_PROCESS_ACCESS)
#define LOGEVT_FILEMON LOGEVT_FLAG(LOGEVT_LAUNCHD_ADD)

typedef struct {
	logevt_header_t hdr;

	const char *subtype;
} xnumon_ops_t;

int logevt_xnumon_ops(logfmt_t *, FILE *, void *) NONNULL(1,2) WUNRES;
int logevt_xnumon_stats(logfmt_t *, FILE *, void *) NONNULL(1,2) WUNRES;
int logevt_image_exec(logfmt_t *, FILE *, void *) NONNULL(1,2) WUNRES;
int logevt_process_access(logfmt_t *, FILE *, void *) NONNULL(1,2) WUNRES;
int logevt_launchd_add(logfmt_t *, FILE *, void *) NONNULL(1,2) WUNRES;

void logevt_init(config_t *);

#endif

