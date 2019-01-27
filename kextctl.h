/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2019, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef KEXTCTL_H
#define KEXTCTL_H

#include "attrib.h"
#include "kext/xnumon.h"

#include <stdio.h>

int kextctl_load(void);
int kextctl_open(void);
const xnumon_msg_t * kextctl_recv(int);
int kextctl_ack(int, const xnumon_msg_t *) NONNULL(2);
int kextctl_stats(int, xnumon_stat_t *) NONNULL(2);
void kextctl_version(FILE *) NONNULL(1);

#endif
