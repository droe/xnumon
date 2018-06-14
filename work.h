/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef WORK_H
#define WORK_H

#include "attrib.h"

#include <stdint.h>

typedef struct {
	uint32_t qsize;
} work_stat_t;

int work_init(void) WUNRES;
void work_fini(void);
void work_submit(void *) NONNULL(1);
void work_stats(work_stat_t *) NONNULL(1);

#endif

