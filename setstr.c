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
 * setstr - static set of strings
 */

#include "setstr.h"

#include "tommy_ext.h"

#include <assert.h>
#include <string.h>
#include <stdio.h>

typedef struct setstr_obj {
	tommy_hashtable_node h_node;
	char *str;
} setstr_obj_t;

static int
setstr_obj_cmp(const void *str, const void *vobj) {
	const setstr_obj_t *obj = vobj;
	return strcmp(obj->str, str);
}

static void
setstr_obj_free(void *vobj) {
	setstr_obj_t *obj = vobj;
	free(obj->str);
	free(obj);
}

/*
 * strings may be (and must be) NULL if buckets is 0.
 * Guarantees to deep free strings even on errors.
 */
int
setstr_init(setstr_t *this, size_t buckets, char **strings) {
	this->bucket_max = bucket_max_for_buckets(buckets);
	this->size = buckets;
	if (buckets == 0) {
		assert(this->bucket_max == 0);
		assert(strings == NULL);
		return 0;
	}

	tommy_hashtable_init(&this->hashtable, this->bucket_max);

	for (size_t i = 0; i < buckets; i++) {
		setstr_obj_t *obj;
		tommy_hash_t h;

		if (setstr_contains(this, strings[i])) {
			free(strings[i]);
			continue;
		}
		obj = malloc(sizeof(setstr_obj_t));
		if (!obj)
			goto errout;
		obj->str = strings[i];
		strings[i] = NULL;
		h = tommy_strhash_u32(0, obj->str);
		tommy_hashtable_insert(&this->hashtable, &obj->h_node,
		                       obj, h);
	}
	if (strings)
		free(strings);
	return 0;
errout:
	for (size_t i = 0; i < buckets; i++) {
		if (strings[i])
			free(strings[i]);
	}
	if (strings)
		free(strings);
	return -1;
}

bool
setstr_contains(setstr_t *this, const char *str) {
	if (this->bucket_max == 0)
		return false;

	return tommy_hashtable_search(&this->hashtable, setstr_obj_cmp, str,
	                              tommy_strhash_u32(0, str));
}

/*
 * Alterantive version of setstr_contains() that supports scopes.
 */
bool
setstr_contains3(setstr_t *this, const char *str, const char *scope) {
	if (this->bucket_max == 0)
		return false;

	/* TODO May be further optimized by keeping track of whether setstr
	 * contains no scoped entries, or setstr contains only scoped entries,
	 * and skipping the respective lookup accordingly */
	if (scope) {
		const size_t sz = strlen(str) + strlen(scope) + 2;
		char key[sz];
		snprintf(key, sz, "%s@%s", str, scope);
		if (setstr_contains(this, key))
			return true;
	}
	return setstr_contains(this, str);
}

size_t
setstr_size(setstr_t *this) {
	return this->size;
}

/*
 * Safe to be called on a bzero'ed setstr_t that was never initialized with
 * setstr_init().
 */
void
setstr_destroy(setstr_t *this) {
	if (this->bucket_max != 0) {
		tommy_hashtable_foreach(&this->hashtable, setstr_obj_free);
		tommy_hashtable_done(&this->hashtable);
	}
	bzero(this, sizeof(setstr_t));
}

