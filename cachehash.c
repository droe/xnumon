/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2019, Daniel Roethlisberger <daniel@roe.ch>.
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
	time_t mtime_sec;
	long   mtime_nsec;
	time_t ctime_sec;
	long   ctime_nsec;
	time_t btime_sec;
	long   btime_nsec;
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
static pthread_mutex_t mutex;

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
              struct timespec *mtime,
              struct timespec *ctime,
              struct timespec *btime) {
	cachehash_obj_t *obj;
	cachehash_key_t key;

	key.dev = dev;
	key.ino = ino;
	key.mtime_sec  = mtime->tv_sec;
	key.mtime_nsec = mtime->tv_nsec;
	key.ctime_sec  = ctime->tv_sec;
	key.ctime_nsec = ctime->tv_nsec;
	key.btime_sec  = btime->tv_sec;
	key.btime_nsec = btime->tv_nsec;
	pthread_mutex_lock(&mutex);
	obj = lrucache_get(&lrucache, &key);
#ifdef DEBUG_CACHE
	fprintf(stderr, "DEBUG_CACHE: hash get %s (%u,%llu,%lu,%lu,%lu)\n",
	                obj ? "HIT" : "MISS",
	                dev, ino, mtime->tv_sec, ctime->tv_sec, btime->tv_sec);
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
cachehash_put(dev_t dev, ino_t ino,
              struct timespec *mtime,
              struct timespec *ctime,
              struct timespec *btime,
              hashes_t *hashes) {
	cachehash_obj_t *obj;

	assert(hashes);

#ifdef DEBUG_CACHE
	fprintf(stderr, "DEBUG_CACHE: hash put (%u,%llu,%lu,%lu,%lu)\n",
	                dev, ino, mtime->tv_sec, ctime->tv_sec, btime->tv_sec);
#endif

	obj = cachehash_obj_new();
	if (!obj)
		return;
	obj->key.dev = dev;
	obj->key.ino = ino;
	obj->key.mtime_sec  = mtime->tv_sec;
	obj->key.mtime_nsec = mtime->tv_nsec;
	obj->key.ctime_sec  = ctime->tv_sec;
	obj->key.ctime_nsec = ctime->tv_nsec;
	obj->key.btime_sec  = btime->tv_sec;
	obj->key.btime_nsec = btime->tv_nsec;
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

