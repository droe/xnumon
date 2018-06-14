/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef LOGDSTSTDOUT_H
#define LOGDSTSTDOUT_H

#include "config.h"
#include "attrib.h"

#include <stdio.h>

int logdststdout_init(config_t *) NONNULL(1) WUNRES;
void logdststdout_fini(void);
FILE * logdststdout_open(void) MALLOC;
int logdststdout_close(FILE *) NONNULL(1) WUNRES;

#endif

