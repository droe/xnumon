/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include "str.h"

bool
str_beginswith(const char *restrict s, const char *restrict prefix) {
	while (*prefix) {
		if (*prefix++ != *s++)
			return false;
	}
	return true;
}



