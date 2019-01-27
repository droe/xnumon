/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2019, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef LRUCACHE_H
#define LRUCACHE_H

#include "attrib.h"

#include "tommylist.h"
#include "tommyhashtbl.h"

/*
 * Trade-off between the number of binaries actively used on a system, the
 * performance curves of the underlying data structures and acceptable memory
 * use.  The number of buckets is the number of cached codesign results and
 * hashes, respectively, not necessarily the effective number of buckets in
 * underlying data structures.
 */
#define LRUCACHE_BUCKETS           12288

typedef void lrucache_free_func_t(void *) NONNULL(1);

typedef struct lrucache_node {
	tommy_hashtable_node h_node;
	tommy_node l_node;
	void *data;
} lrucache_node_t;

typedef struct lrucache_stat {
	uint32_t size;
	uint32_t used;
	uint64_t puts;
	uint64_t gets;
	uint64_t hits;
	uint64_t misses;
	uint64_t invalids;
} lrucache_stat_t;

typedef struct lrucache {
	tommy_hashtable hashtable;
	tommy_list list;
	tommy_count_t bucket_max;
	size_t hashsz;
	size_t compsz;
	size_t condsz;
	lrucache_free_func_t *freefunc;
	lrucache_stat_t stat;
} lrucache_t;

void lrucache_init(lrucache_t *, tommy_count_t,
                   size_t, size_t, size_t,
                   lrucache_free_func_t *) NONNULL(1);
void lrucache_put(lrucache_t *, lrucache_node_t *, void *) NONNULL(1,2,3);
void * lrucache_get(lrucache_t *, void *) NONNULL(1,2) WUNRES;
void lrucache_stats(lrucache_t *, lrucache_stat_t *) NONNULL(1,2);
void lrucache_flush(lrucache_t *) NONNULL(1);
void lrucache_destroy(lrucache_t *) NONNULL(1);

#endif

