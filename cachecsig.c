/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2019, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include "cachecsig.h"

#include <string.h>
#include <assert.h>
#include <pthread.h>
#ifdef DEBUG_CACHE
#include <stdio.h>
#endif

#define CACHECSIG_BUCKETS       LRUCACHE_BUCKETS

typedef struct {
	hashes_t hashes;
	codesign_t *codesign;

	lrucache_node_t node;
} cachecsig_obj_t;

static cachecsig_obj_t *
cachecsig_obj_new() {
	cachecsig_obj_t *obj;

	obj = malloc(sizeof(cachecsig_obj_t));
	if (!obj)
		return NULL;
	bzero(obj, sizeof(cachecsig_obj_t));
	return obj;
}

static void
cachecsig_obj_free(void *vobj) {
	cachecsig_obj_t *obj = vobj;
	assert(obj);
	if (obj->codesign)
		codesign_free(obj->codesign);
	free(obj);
}

static lrucache_t lrucache;
static pthread_mutex_t mutex;

void
cachecsig_init(void) {
	pthread_mutex_init(&mutex, NULL);
	/* we could use only MD5SZ if we were sure that MD5 is present */
	lrucache_init(&lrucache, CACHECSIG_BUCKETS,
	              sizeof(hashes_t), sizeof(hashes_t), 0,
	              cachecsig_obj_free);
}

void
cachecsig_fini(void) {
	lrucache_destroy(&lrucache);
	pthread_mutex_destroy(&mutex);
}

/*
 * Can return NULL due to errno == ENOMEM
 */
codesign_t *
cachecsig_get(hashes_t *hashes) {
	cachecsig_obj_t *obj;
	codesign_t *cs;

	assert(hashes);

	pthread_mutex_lock(&mutex);
	obj = lrucache_get(&lrucache, hashes);
#ifdef DEBUG_CACHE
	fprintf(stderr, "DEBUG_CACHE: codesig get %s\n",
	                obj ? "HIT" : "MISS");
#endif
	if (!obj) {
		pthread_mutex_unlock(&mutex);
		return NULL;
	}
	cs = codesign_dup(obj->codesign);
	pthread_mutex_unlock(&mutex);
	return cs;
}

void
cachecsig_put(hashes_t *hashes, codesign_t *codesign) {
	cachecsig_obj_t *obj;

	assert(hashes);
	assert(codesign);

#ifdef DEBUG_CACHE
	fprintf(stderr, "DEBUG_CACHE: codesig put\n");
#endif

	obj = cachecsig_obj_new();
	if (!obj)
		return;
	memcpy(&obj->hashes, hashes, sizeof(hashes_t));
	obj->codesign = codesign_dup(codesign);
	pthread_mutex_lock(&mutex);
	lrucache_put(&lrucache, &obj->node, obj);
	pthread_mutex_unlock(&mutex);
}

void
cachecsig_stats(lrucache_stat_t *st) {
	pthread_mutex_lock(&mutex);
	lrucache_stats(&lrucache, st);
	pthread_mutex_unlock(&mutex);
}

