/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include "logutl.h"

#include <string.h>

void
logutl_fwrite_hex(FILE *f, const unsigned char *buf, size_t sz) {
	for (size_t i = 0; i < sz; i++) {
		fprintf(f, "%02x", buf[i]);
	}
}

void
logutl_fwrite_timespec(FILE *f, struct timespec *tv) {
	char buf[20];
	struct tm stm;

	gmtime_r(&tv->tv_sec, &stm);
	strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &stm);
	fprintf(f, "%s.%09luZ", buf, tv->tv_nsec);
}


