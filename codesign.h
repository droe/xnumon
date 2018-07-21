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
#include <stdio.h>

typedef struct {
	int result;
#define CODESIGN_RESULT_UNSIGNED      1
#define CODESIGN_RESULT_GOOD          2
#define CODESIGN_RESULT_BAD           3
#define CODESIGN_RESULT_ERROR         4
	int origin;
#define CODESIGN_ORIGIN_APPLE_SYSTEM  1
#define CODESIGN_ORIGIN_MAC_APP_STORE 2
#define CODESIGN_ORIGIN_DEVELOPER_ID  3
#define CODESIGN_ORIGIN_APPLE_GENERIC 4
	long error;
	char *ident;
	unsigned char *cdhash;
	size_t cdhashsz;
	char *teamid;
	char *devid;
} codesign_t;

#define codesign_is_good(CS) \
	((CS)->result == CODESIGN_RESULT_GOOD)
#define codesign_is_apple_system(CS) \
	((CS)->origin == CODESIGN_ORIGIN_APPLE_SYSTEM)

codesign_t * codesign_new(const char *) MALLOC NONNULL(1);
codesign_t * codesign_dup(const codesign_t *) MALLOC NONNULL(1);
void codesign_free(codesign_t *) NONNULL(1);

const char * codesign_result_s(codesign_t *) NONNULL(1);
const char * codesign_origin_s(codesign_t *) NONNULL(1);
void codesign_fprint(FILE *, codesign_t *) NONNULL(1,2);

int codesign_init(void) WUNRES;
void codesign_fini(void);

#endif

