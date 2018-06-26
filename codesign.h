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

typedef struct {
	char *result;
	long error;
	char *ident;
	char *teamid;
	int crtc;
	char **crtv;
} codesign_t;

codesign_t * codesign_new(const char *) MALLOC NONNULL(1);
codesign_t * codesign_dup(const codesign_t *) MALLOC NONNULL(1);
void codesign_free(codesign_t *) NONNULL(1);

#endif

