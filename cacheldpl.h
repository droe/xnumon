/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2019, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef CACHELDPL_H
#define CACHELDPL_H

#include "lrucache.h"
#include "attrib.h"

#include <sys/types.h>
#include <time.h>
#include <stdbool.h>

void cacheldpl_init(void);
void cacheldpl_fini(void);
bool cacheldpl_get(dev_t, ino_t, time_t, time_t, time_t);
void cacheldpl_put(dev_t, ino_t, time_t, time_t, time_t);
void cacheldpl_stats(lrucache_stat_t *) NONNULL(1);

#endif

