/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef TEST_GETPATH_H
#define TEST_GETPATH_H

#include <stdint.h>
#include <stdlib.h>
#include <mach-o/dyld.h>

static inline const char *
getpath(void) {
	char pathbuf[1024];
	uint32_t size = sizeof(pathbuf);
	if (_NSGetExecutablePath(pathbuf, &size) != 0)
		return NULL;
	return realpath(pathbuf, NULL);
}

#endif
