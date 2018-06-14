/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef LAUNCHD_H
#define LAUNCHD_H

#include "attrib.h"

int launchd_plist_write(const char *, const char *,
                        const char *, int, char *[]) NONNULL(1,3,5);

#endif

