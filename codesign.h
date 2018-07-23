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

#include "config.h"
#include "attrib.h"

#include <sys/types.h>
#include <stdbool.h>
#include <stdio.h>

typedef struct {
	int result;
#define CODESIGN_RESULT_NONE          0
#define CODESIGN_RESULT_UNSIGNED      1 /* no signature */
#define CODESIGN_RESULT_GOOD          2 /* signature with trusted anchor */
#define CODESIGN_RESULT_UNTRUSTED     3 /* signature with untrusted anchor */
#define CODESIGN_RESULT_BAD           4 /* bad signature */
#define CODESIGN_RESULT_ERROR         5 /* error */
	int origin;
#define CODESIGN_ORIGIN_NONE          0
#define CODESIGN_ORIGIN_APPLE_SYSTEM  1
#define CODESIGN_ORIGIN_MAC_APP_STORE 2
#define CODESIGN_ORIGIN_DEVELOPER_ID  3
#define CODESIGN_ORIGIN_APPLE_GENERIC 4
#define CODESIGN_ORIGIN_TRUSTED_CA    5
	unsigned char *cdhash;
	size_t cdhashsz;
	char *ident;
	char *teamid;
	char *certcn;
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

int codesign_init(config_t *) WUNRES NONNULL(1);
void codesign_fini(void);

#endif

