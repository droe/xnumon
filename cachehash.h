/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef CACHEHASH_H
#define CACHEHASH_H

#include "lrucache.h"
#include "hashes.h"
#include "attrib.h"

#include <sys/types.h>
#include <time.h>
#include <stdbool.h>

void cachehash_init(void);
void cachehash_fini(void);
bool cachehash_get(hashes_t *,
                   dev_t, ino_t,
                   struct timespec *,
                   struct timespec *,
                   struct timespec *) NONNULL(1,4,5,6);
void cachehash_put(dev_t, ino_t,
                   struct timespec *,
                   struct timespec *,
                   struct timespec *,
                   hashes_t *) NONNULL(3,4,5,6);
void cachehash_stats(lrucache_stat_t *) NONNULL(1);

#endif

