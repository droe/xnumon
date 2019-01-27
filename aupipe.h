/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2019, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef AUPIPE_H
#define AUPIPE_H

#include "attrib.h"

#include <stdio.h>

typedef struct {
	unsigned int qlen;
	unsigned int qlimit;
	unsigned int inserts;
	unsigned int reads;
	unsigned int drops;
	/* truncates not implemented by OpenBSM */
} aupipe_stat_t;

FILE * aupipe_fopen(unsigned int) MALLOC;
int aupipe_open(unsigned int);
void aupipe_stats(int, aupipe_stat_t *) NONNULL(2);

#endif
