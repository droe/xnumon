/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2019, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef TOMMY_EXT_H
#define TOMMY_EXT_H

/*
 * Trivial extensions to TommyDS, dual-licenced under the licensing terms of
 * xnumon (OSL 3.0) and TommyDS (2-Clause BSD).
 */

#include "minmax.h"

#include "tommytypes.h"

/* go for 75% of next power of two to stay clear of hashtable
 * performance drop but also avoiding overmuch slack space */
static inline size_t
bucket_max_for_buckets(size_t buckets) {
	size_t bmax;

	if (buckets == 0)
		return 0;

	bmax = (tommy_roundup_pow2_u32(buckets) >> 2) * 3;
	if (buckets > bmax)
		bmax <<= 1;
	return max(bmax, (size_t)16);
}

#endif

