/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef LOGUTL_H
#define LOGUTL_H

#include "attrib.h"

#include <stdio.h>
#include <time.h>

void logutl_fwrite_hex(FILE *, const unsigned char *, size_t) NONNULL(1,2);
void logutl_fwrite_timespec(FILE *, struct timespec *) NONNULL(1,2);

#endif

