/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef LOGDSTFILE_H
#define LOGDSTFILE_H

#include "config.h"
#include "attrib.h"

#include <stdio.h>

int logdstfile_init(config_t *) NONNULL(1) WUNRES;
int logdstfile_reinit(void);
void logdstfile_fini(void);
FILE * logdstfile_open(void) MALLOC;
int logdstfile_close(FILE *) NONNULL(1) WUNRES;

#endif

