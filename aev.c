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

#include <stdlib.h>
#include <string.h>
#include <assert.h>

/*
 * Construct a newly allocated argv/env-style vector, copying over *aec*
 * strings from *aev*.  The resulting vector will be NULL-terminated and no
 * separate count of the number of elements needs to be stored.  Performs a
 * deep copy, i.e. the memory in *aev* does not need to be kept around.
 */
char **
aev_new(size_t aec, char **aev) {
	size_t sz = 0;
	char **buf;
	char *sp, *dp;

	if (aec == 0)
		return NULL;
	for (size_t i = 0; i < aec; i++)
		sz += sizeof(char *) + strlen(aev[i]) + 1;
	sz += sizeof(char *);
	buf = malloc(sz);
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

