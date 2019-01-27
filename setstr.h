/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2019, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef SETSTR_H
#define SETSTR_H

#include "attrib.h"

#include "tommyhashtbl.h"

#include <stddef.h>
#include <stdbool.h>

typedef struct setstr {
	tommy_hashtable hashtable;
	tommy_count_t bucket_max;
	size_t size;
} setstr_t;

int setstr_init(setstr_t *, size_t, char **) NONNULL(1) WUNRES;
bool setstr_contains(setstr_t *, const char *) NONNULL(1,2) WUNRES;
bool setstr_contains3(setstr_t *, const char *, const char *)
     NONNULL(1,2) WUNRES;
size_t setstr_size(setstr_t *) NONNULL(1);
void setstr_destroy(setstr_t *) NONNULL(1);

#endif

