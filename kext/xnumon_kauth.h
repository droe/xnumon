/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2019, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef XNUMON_KAUTH_H
#define XNUMON_KAUTH_H

#include <mach/mach_types.h>

void xnumon_kauth_release(uint64_t);
void xnumon_kauth_stats(uint64_t *, uint64_t *, uint64_t *, uint64_t *,
                        uint32_t *);
kern_return_t xnumon_kauth_start(void);
kern_return_t xnumon_kauth_stop(void);

#endif

