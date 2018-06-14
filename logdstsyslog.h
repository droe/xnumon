/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef LOGDSTSYSLOG_H
#define LOGDSTSYSLOG_H

#include "config.h"
#include "attrib.h"

#include <stdio.h>

int logdstsyslog_init(config_t *) NONNULL(1) WUNRES;
void logdstsyslog_fini(void);
FILE * logdstsyslog_open(void) MALLOC;
int logdstsyslog_close(FILE *) NONNULL(1) WUNRES;

#endif

