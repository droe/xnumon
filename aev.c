/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include "aev.h"

#include "str.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

/*
 * sz is the total length of all the strings in aev including terminating
 * zeroes.
 */
static char **
aev_new_internal(size_t aec, char **aev, size_t sz) {
	char **buf;
	char *sp, *dp;

	sz += sizeof(char *) * (aec + 1);
	buf = malloc(sz);
	if (!buf)
		return NULL;
	buf[aec] = NULL;
	dp = (char *)&buf[aec+1];
	for (size_t i = 0; i < aec; i++) {
		buf[i] = dp;
		sp = aev[i];
		while (*sp)
			*(dp++) = *(sp++);
		*(dp++) = '\0';
	}
	assert(dp == ((char *)buf) + sz);
	return buf;
}

/*
 * Construct a newly allocated argv/env-style vector, copying over *aec*
 * strings from *aev*.  The resulting vector will be NULL-terminated and no
 * separate count of the number of elements needs to be stored.  Performs a
 * deep copy, i.e. the memory in *aev* does not need to be kept around.
 *
 * Returns NULL if aec is 0, aev is NULL, or on memory allocation failure, in
 * which case errno is set to ENOMEM.
 */
char **
aev_new(size_t aec, char **aev) {
	size_t sz = 0;

	errno = 0;
	if (aec == 0 || !aev)
		return NULL;
	for (size_t i = 0; i < aec; i++)
		sz += strlen(aev[i]) + 1;
	return aev_new_internal(aec, aev, sz);
}

/*
 * Like aev_new, but only considers entries in aev which begin with prefix.
 * Returns NULL if no entry in aev begins with prefix.
 */
char **
aev_new_prefix(size_t aec, char **aev, const char *prefix) {
	size_t sz = 0;
	char *filtered_aev[aec];
	size_t filtered_aec = 0;

	if (!prefix)
		return aev_new(aec, aev);

	errno = 0;
	if (aec == 0 || !aev)
		return NULL;
	for (size_t i = 0; i < aec; i++) {
		if (str_beginswith(aev[i], prefix)) {
			filtered_aev[filtered_aec++] = aev[i];
			sz += strlen(aev[i]) + 1;
		}
	}
	if (sz == 0)
		return NULL;
	return aev_new_internal(filtered_aec, filtered_aev, sz);
}

