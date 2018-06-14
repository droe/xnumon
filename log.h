/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef LOG_H
#define LOG_H

#include "logevt.h"
#include "config.h"
#include "attrib.h"

#include <stdint.h>
#include <stdio.h>

int logfmt_parse(config_t *, const char *) NONNULL(1,2) WUNRES;
const char *logfmt_s(config_t *) NONNULL(1);
int logdst_parse(config_t *, const char *) NONNULL(1,2) WUNRES;
const char *logdst_s(config_t *) NONNULL(1);

int log_init(config_t *) NONNULL(1) WUNRES;
int log_reinit(void) WUNRES;
void log_fini(void);

typedef struct {
	uint32_t qsize;
	uint64_t errors;
	uint64_t counts[LOGEVT_SIZE];
} log_stat_t;

void log_submit(void *) NONNULL(1);
void log_stats(log_stat_t *) NONNULL(1);
void log_version(FILE *) NONNULL(1);

int log_event_xnumon_start(void) WUNRES;
int log_event_xnumon_stop(void) WUNRES;
int log_event_xnumon_stats(void) WUNRES;

#endif

