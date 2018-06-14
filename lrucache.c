/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

/*
 * Generic, fixed-size least-recently-used cache based on tommy_hashtable and
 * tommy_list.  The implementation is not thread-safe.
 */

#include "lrucache.h"

#include <assert.h>
#include <string.h>

typedef struct {
	void *key;
	size_t sz;
} compfunc_ctx_t;

static int
compfunc(const void *arg, const void *obj) {
	const compfunc_ctx_t *ctx = arg;
	const lrucache_node_t *lrunode = obj;
	return memcmp(lrunode->data, ctx->key, ctx->sz);
}

static void
freeargfunc(void *arg, void *obj) {
	lrucache_node_t *node = obj;
	tommy_foreach_func *freefunc = (tommy_foreach_func *)arg;
	freefunc(node->data);
}

/*
 * Initialize an already allocated tommy_lrucache struct with the given
 * number of effectively usable cache buckets.  The initial `hashsz', `compsz'
 * and `condsz' bytes of stored objects are used as input to the hash function,
 * as key for key comparison in get and put operations, and as object validity
 * criteria as part of get operations.  If `hashsz' and `compsz' are equal, the
 * full number of key bytes is also used as hash, which is the right thing to
 * do when in doubt.  If `condsz' is 0, objects are not checked for validity.
 * The cache uses `freefunc' to free objects for cache eviction.
 */
void
lrucache_init(lrucache_t *this, tommy_count_t buckets,
              size_t hashsz, size_t compsz, size_t condsz,
              lrucache_free_func_t *freefunc) {
	assert(this);
	assert(freefunc);

	/* go for 75% of next power of two to stay clear of hashtable
	 * performance drop but also avoiding overmuch slack space */
	this->bucket_max = (tommy_roundup_pow2_u32(buckets) >> 2) * 3;
	if (buckets > this->bucket_max)
		this->bucket_max <<= 1;
	this->hashsz = hashsz;
	this->compsz = compsz;
	this->condsz = condsz;
	this->freefunc = freefunc;
	bzero(&this->stat, sizeof(this->stat));
	this->stat.size = this->bucket_max;
	tommy_hashtable_init(&this->hashtable, this->bucket_max);
	tommy_list_init(&this->list);
}

/*
 * Put an object `data' into the cache at the beginning of the LRU queue.
 * If an object with matching key is already in the cache, `data' is freed and
 * the object already in the cache is moved to the beginning of the LRU queue.
 * If the cache is already at maximum capacity, the object at the end of the
 * LRU queue will be freed using `freefunc'.
 *
 * The inital `compsz` bytes of the object must not be modified while the
 * object remains stored in the cache.
 */
void
lrucache_put(lrucache_t *this, lrucache_node_t *node, void *data) {
	compfunc_ctx_t ctx;
	tommy_node *lnode;
	lrucache_node_t *lrunode;
	tommy_hash_t h;

	assert(this);
	assert(node);
	assert(data);

	this->stat.puts++;
	if (tommy_hashtable_count(&this->hashtable) == this->bucket_max) {
		lnode = tommy_list_tail(&this->list);
		lrunode = lnode->data;
		tommy_list_remove_existing(&this->list, lnode);
		tommy_hashtable_remove_existing(&this->hashtable,
		                                &lrunode->h_node);
		this->freefunc(lrunode->data);
	}
	ctx.key = data;
	ctx.sz = this->compsz;
	h = tommy_hash_u32(0, data, this->hashsz);
	lrunode = tommy_hashtable_search(&this->hashtable, compfunc, &ctx, h);
	if (lrunode) {
		this->freefunc(data);
		return;
	}
	node->data = data;
	tommy_hashtable_insert(&this->hashtable, &node->h_node, node, h);
	tommy_list_insert_head(&this->list, &node->l_node, node);
}

/*
 * Get an object from the cache, identified by the initial `compsz' bytes of
 * `key' matching the stored object.  If the found object does not match the
 * first `condsz' bytes of key, it is considered invalid and will be freed
 * using `freefunc`.
 *
 * Returns a pointer to the stored object.  The inital `compsz` bytes of the
 * object must not be modified while the object remains stored in the cache.
 * Returns NULL if no such object was found or if the found object failed the
 * validity condition.
 */
void *
lrucache_get(lrucache_t *this, void *key) {
	compfunc_ctx_t ctx;
	lrucache_node_t *lrunode;

	assert(this);
	assert(key);

	this->stat.gets++;
	ctx.key = key;
	ctx.sz = this->compsz;
	lrunode = tommy_hashtable_search(&this->hashtable, compfunc, &ctx,
	                                 tommy_hash_u32(0, key, this->hashsz));
	if (!lrunode) {
		this->stat.misses++;
		return NULL;
	}
	if ((this->condsz > this->compsz) &&
	    !!memcmp(((unsigned char *)lrunode->data) + this->compsz,
	             ((unsigned char *)key) + this->compsz,
	             this->condsz - this->compsz)) {
		tommy_hashtable_remove_existing(&this->hashtable,
		                                &lrunode->h_node);
		tommy_list_remove_existing(&this->list, &lrunode->l_node);
		this->freefunc(lrunode->data);
		this->stat.invalids++;
		return NULL;
	}
	if (&lrunode->l_node != tommy_list_head(&this->list)) {
		tommy_list_remove_existing(&this->list, &lrunode->l_node);
		tommy_list_insert_head(&this->list, &lrunode->l_node, lrunode);
	}
	this->stat.hits++;
	return lrunode->data;
}

/*
 * Return statistics.
 */
void
lrucache_stats(lrucache_t *this, lrucache_stat_t *st) {
	assert(this);
	assert(st);

	this->stat.used = tommy_hashtable_count(&this->hashtable);
	*st = this->stat;
}

/*
 * Flush the cache, resulting in an empty initialized cache.
 * Objects stored in the cache will be freed using `freefunc'.
 */
void
lrucache_flush(lrucache_t *this) {
	assert(this);

	lrucache_destroy(this);
	tommy_hashtable_init(&this->hashtable, this->bucket_max);
	tommy_list_init(&this->list);
}

/*
 * Free all resources associated with the cache.
 * Objects stored in the cache will be freed using `freefunc'.
 */
void
lrucache_destroy(lrucache_t *this) {
	assert(this);

	tommy_hashtable_done(&this->hashtable);
	tommy_list_foreach_arg(&this->list, freeargfunc,
	                       (void *)this->freefunc);
}

