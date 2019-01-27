/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2019, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef CACHECSIG_H
#define CACHECSIG_H

#include "lrucache.h"
#include "hashes.h"
#include "codesign.h"
#include "attrib.h"

void cachecsig_init(void);
void cachecsig_fini(void);
codesign_t * cachecsig_get(hashes_t *) MALLOC NONNULL(1);
void cachecsig_put(hashes_t *, codesign_t *) NONNULL(1,2);
void cachecsig_stats(lrucache_stat_t *) NONNULL(1);

#endif

