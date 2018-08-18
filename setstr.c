/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include "setstr.h"

#include "tommy_ext.h"

#include <assert.h>
#include <string.h>
#include <stdio.h>

typedef struct setstr_node {
	tommy_hashtable_node h_node;
	char *str;
} setstr_node_t;

static int
compfunc(const void *str, const void *obj) {
	const setstr_node_t *node = obj;
	return strcmp(node->str, str);
}

/*
 * strings may be NULL only if buckets is 0.
 * Guarantees to deep free strings even on errors.
 */
int
setstr_init(setstr_t *this, size_t buckets, char **strings) {
	this->bucket_max = bucket_max_for_buckets(buckets);
	this->size = buckets;
	tommy_hashtable_init(&this->hashtable, this->bucket_max);

	for (size_t i = 0; i < buckets; i++) {
		setstr_node_t *node;
		tommy_hash_t h;

		if (setstr_contains(this, strings[i])) {
			free(strings[i]);
			continue;
		}
		node = malloc(sizeof(setstr_node_t));
		if (!node)
			goto errout;
		node->str = strings[i];
		strings[i] = NULL;
		h = tommy_strhash_u32(0, node->str);
		tommy_hashtable_insert(&this->hashtable, &node->h_node,
		                       node, h);
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
	setstr_node_t *node;

	node = tommy_hashtable_search(&this->hashtable, compfunc, str,
	                              tommy_strhash_u32(0, str));
	return node != NULL;
}

/*
 * Alterantive version of setstr_contains() that supports scopes.
 */
bool
setstr_contains3(setstr_t *this, const char *str, const char *scope) {
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
	if (this->bucket_max == 0)
		return;
	tommy_hashtable_foreach(&this->hashtable, free);
	tommy_hashtable_done(&this->hashtable);
	bzero(this, sizeof(setstr_t));
}

