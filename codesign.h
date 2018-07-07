/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef CODESIGN_H
#define CODESIGN_H

#include "attrib.h"

#include <sys/types.h>
#include <stdbool.h>

typedef struct {
	int result;
#define CODESIGN_RESULT_UNSIGNED        1
#define CODESIGN_RESULT_GOOD            2
#define CODESIGN_RESULT_BAD             4
#define CODESIGN_RESULT_ERROR           8
#define CODESIGN_RESULT_APPLE          16 /* set for com.apple binaries */
	long error;
	char *ident;
	unsigned char *cdhash;
	size_t cdhashsz;
	char *teamid;
	char *devid;
} codesign_t;

codesign_t * codesign_new(const char *) MALLOC NONNULL(1);
codesign_t * codesign_dup(const codesign_t *) MALLOC NONNULL(1);
void codesign_free(codesign_t *) NONNULL(1);

const char * codesign_result_s(codesign_t *) NONNULL(1);
bool codesign_is_apple(codesign_t *) NONNULL(1);

#endif

