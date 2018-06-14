/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef TIME_H
#define TIME_H

#include "attrib.h"

#include <time.h>
#include <stdbool.h>

bool timespec_greater(struct timespec *, struct timespec *) NONNULL(1,2) WUNRES;
bool timespec_equal(struct timespec *, struct timespec *) NONNULL(1,2) WUNRES;
int timespec_nanotime(struct timespec *) NONNULL(1) WUNRES;

#endif

