/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef STR_H
#define STR_H

#include "attrib.h"

#include <stdbool.h>

bool str_beginswith(const char *restrict, const char *restrict) NONNULL(1,2);

#endif

