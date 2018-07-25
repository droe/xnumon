/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef DEBUG_H
#define DEBUG_H

#include "attrib.h"

#include <stdio.h>

void debug_init(void);
void debug_fini(void);
void debug_fprintf(FILE *, const char *, ...) NONNULL(1,2);

#define DEBUG(cond, topic, fmt, ...) \
	if (cond) { \
		debug_fprintf(stderr, "%s %s " fmt "\n", \
		                      __func__, topic, ##__VA_ARGS__); \
	}

#endif

