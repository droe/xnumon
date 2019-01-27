/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2019, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include "debug.h"

#include "logutl.h"
#include "time.h"

#include <stdio.h>
#include <stdarg.h>
#include <pthread.h>

static pthread_mutex_t mutex;

void
debug_init(void) {
	pthread_mutex_init(&mutex, NULL);
}

void
debug_fini(void) {
	pthread_mutex_destroy(&mutex);
}

void
debug_fprintf(FILE *f, const char *fmt, ...) {
	va_list ap;
	struct timespec tv;
	char buf[20];
	struct tm stm;

	pthread_mutex_lock(&mutex);
	if (timespec_nanotime(&tv) != -1) {
		gmtime_r(&tv.tv_sec, &stm);
		strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &stm);
		fprintf(f, "%s.%06luZ ", buf, tv.tv_nsec / 1000);
	}
	va_start(ap, fmt);
	vfprintf(f, fmt, ap);
	va_end(ap);
	pthread_mutex_unlock(&mutex);
}

