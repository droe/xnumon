/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include "cacheldpl.h"

#include <string.h>
#include <assert.h>
#include <pthread.h>
#ifdef DEBUG_CACHE
#include <stdio.h>
#endif

/*
 * It is not uncommon for systems to have daemons and agents in the high
 * hundreds; go above 1k by default.
 */
#define CACHELDPL_BUCKETS       1536

typedef struct __attribute__((packed)) {
	ino_t ino;
	dev_t dev;
	time_t mtime;
	time_t ctime;
	time_t btime;
} cacheldpl_key_t;

typedef struct {
	cacheldpl_key_t key;
	/* no data payload */
	lrucache_node_t node;
} cacheldpl_obj_t;

static cacheldpl_obj_t *
cacheldpl_obj_new() {
	cacheldpl_obj_t *obj;

	obj = malloc(sizeof(cacheldpl_obj_t));
	if (!obj)
		return NULL;
	bzero(obj, sizeof(cacheldpl_obj_t));
	return obj;
}

static void
cacheldpl_obj_free(void *obj) {
	assert(obj);
	free(obj);
}

static lrucache_t lrucache;
static pthread_mutex_t mutex;

void
cacheldpl_init(void) {
	pthread_mutex_init(&mutex, NULL);
	lrucache_init(&lrucache, CACHELDPL_BUCKETS,
	              sizeof(dev_t) + sizeof(ino_t),
	              sizeof(dev_t) + sizeof(ino_t),
	              sizeof(cacheldpl_key_t),
	              cacheldpl_obj_free);
}

void
cacheldpl_fini(void) {
	lrucache_destroy(&lrucache);
	pthread_mutex_destroy(&mutex);
}

bool
cacheldpl_get(dev_t dev, ino_t ino,
              time_t mtime, time_t ctime, time_t btime) {
	cacheldpl_obj_t *obj;
	cacheldpl_key_t key;

	key.dev = dev;
	key.ino = ino;
	key.mtime = mtime;
	key.ctime = ctime;
	key.btime = btime;
	pthread_mutex_lock(&mutex);
	obj = lrucache_get(&lrucache, &key);
#ifdef DEBUG_CACHE
	fprintf(stderr, "DEBUG_CACHE: ldpl get %s (%u,%llu,%lu,%lu,%lu)\n",
	                obj ? "HIT" : "MISS",
	                dev, ino, mtime, ctime, btime);
#endif
	pthread_mutex_unlock(&mutex);
	return !!obj;
}

void
cacheldpl_put(dev_t dev, ino_t ino, time_t mtime, time_t ctime, time_t btime) {
	cacheldpl_obj_t *obj;

#ifdef DEBUG_CACHE
	fprintf(stderr, "DEBUG_CACHE: ldpl put (%u,%llu,%lu,%lu,%lu)\n",
	                dev, ino, mtime, ctime, btime);
#endif

	obj = cacheldpl_obj_new();
	if (!obj)
		return;
	obj->key.dev = dev;
	obj->key.ino = ino;
	obj->key.mtime = mtime;
	obj->key.ctime = ctime;
	obj->key.btime = btime;
	pthread_mutex_lock(&mutex);
	lrucache_put(&lrucache, &obj->node, obj);
	pthread_mutex_unlock(&mutex);
}

void
cacheldpl_stats(lrucache_stat_t *st) {
	pthread_mutex_lock(&mutex);
	lrucache_stats(&lrucache, st);
	pthread_mutex_unlock(&mutex);
}

