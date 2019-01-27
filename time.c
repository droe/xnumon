/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2019, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include "time.h"

#include <sys/time.h>

bool
timespec_greater_plus(struct timespec *tv1, struct timespec *tv2, time_t s) {
	if (tv1->tv_sec == tv2->tv_sec + s) {
		return (tv1->tv_nsec > tv2->tv_nsec);
	} else {
		return (tv1->tv_sec > tv2->tv_sec + s);
	}
}

bool
timespec_greater(struct timespec *tv1, struct timespec *tv2) {
	if (tv1->tv_sec == tv2->tv_sec) {
		return (tv1->tv_nsec > tv2->tv_nsec);
	} else {
		return (tv1->tv_sec > tv2->tv_sec);
	}
}

bool
timespec_equal(struct timespec *tv1, struct timespec *tv2) {
	return (tv1->tv_sec == tv2->tv_sec) && (tv1->tv_nsec == tv2->tv_nsec);
}

int
timespec_nanotime(struct timespec *tv) {
#ifdef CLOCK_REALTIME
	return clock_gettime(CLOCK_REALTIME, tv);
#else
	struct timeval now;
	if (gettimeofday(&now, NULL) == -1)
		return -1;
	tv->tv_sec = now.tv_sec;
	tv->tv_nsec = now.tv_usec * 1000;
	return 0;
#endif
}

