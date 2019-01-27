/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2019, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef OS_H
#define OS_H

#include "attrib.h"

int os_init(void) WUNRES;
void os_fini(void);
const char * os_name(void);
const char * os_version(void);
const char * os_build(void);

#endif

