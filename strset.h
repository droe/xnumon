/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2019, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef STRSET_H
#define STRSET_H

#include "attrib.h"

#include "tommyhashtbl.h"

#include <stddef.h>
#include <stdbool.h>

typedef struct strset {
	tommy_hashtable hashtable;
	tommy_count_t bucket_max;
	size_t size;
} strset_t;

int strset_init(strset_t *, size_t, char **) NONNULL(1) WUNRES;
bool strset_contains(strset_t *, const char *) NONNULL(1,2) WUNRES;
bool strset_contains3(strset_t *, const char *, const char *)
     NONNULL(1,2) WUNRES;
size_t strset_size(strset_t *) NONNULL(1);
void strset_destroy(strset_t *) NONNULL(1);

#endif

