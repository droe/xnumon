/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include "cachehash.h"

#include <string.h>
#include <assert.h>
#include <pthread.h>
#ifdef DEBUG_CACHE
#include <stdio.h>
#endif

#define CACHEHASH_BUCKETS       LRUCACHE_BUCKETS

typedef struct __attribute__((packed)) {
	ino_t ino;
	dev_t dev;
	time_t mtime;
	time_t ctime;
	time_t btime;
} cachehash_key_t;

typedef struct {
	cachehash_key_t key;
	hashes_t hashes;
	lrucache_node_t node;
} cachehash_obj_t;

static cachehash_obj_t *
cachehash_obj_new() {
	cachehash_obj_t *obj;

	obj = malloc(sizeof(cachehash_obj_t));
	if (!obj)
		return NULL;
	bzero(obj, sizeof(cachehash_obj_t));
	return obj;
}

static void
cachehash_obj_free(void *obj) {
	assert(obj);
	free(obj);
}

static lrucache_t lrucache;
pthread_mutex_t mutex;

void
cachehash_init(void) {
	pthread_mutex_init(&mutex, NULL);
	lrucache_init(&lrucache, CACHEHASH_BUCKETS,
	              sizeof(dev_t) + sizeof(ino_t),
	              sizeof(dev_t) + sizeof(ino_t),
	              sizeof(cachehash_key_t),
	              cachehash_obj_free);
}

void
cachehash_fini(void) {
	lrucache_destroy(&lrucache);
	pthread_mutex_destroy(&mutex);
}

bool
cachehash_get(hashes_t *hashes,
              dev_t dev, ino_t ino,
              time_t mtime, time_t ctime, time_t btime) {
	cachehash_obj_t *obj;
	cachehash_key_t key;

	key.dev = dev;
	key.ino = ino;
	key.mtime = mtime;
	key.ctime = ctime;
	key.btime = btime;
	pthread_mutex_lock(&mutex);
	obj = lrucache_get(&lrucache, &key);
#ifdef DEBUG_CACHE
	fprintf(stderr, "DEBUG_CACHE: hash get %s (%u,%llu,%lu,%lu,%lu)\n",
	                obj ? "HIT" : "MISS",
	                dev, ino, mtime, ctime, btime);
#endif
	if (!obj) {
		pthread_mutex_unlock(&mutex);
		return false;
	}
	memcpy(hashes, &obj->hashes, sizeof(hashes_t));
	pthread_mutex_unlock(&mutex);
	return true;
}

void
cachehash_put(dev_t dev, ino_t ino, time_t mtime, time_t ctime, time_t btime,
              hashes_t *hashes) {
	cachehash_obj_t *obj;

	assert(hashes);

#ifdef DEBUG_CACHE
	fprintf(stderr, "DEBUG_CACHE: hash put (%u,%llu,%lu,%lu,%lu)\n",
	                dev, ino, mtime, ctime, btime);
#endif

	obj = cachehash_obj_new();
	if (!obj)
		return;
	obj->key.dev = dev;
	obj->key.ino = ino;
	obj->key.mtime = mtime;
	obj->key.ctime = ctime;
	obj->key.btime = btime;
	memcpy(&obj->hashes, hashes, sizeof(hashes_t));
	pthread_mutex_lock(&mutex);
	lrucache_put(&lrucache, &obj->node, obj);
	pthread_mutex_unlock(&mutex);
}

void
cachehash_stats(lrucache_stat_t *st) {
	pthread_mutex_lock(&mutex);
	lrucache_stats(&lrucache, st);
	pthread_mutex_unlock(&mutex);
}

