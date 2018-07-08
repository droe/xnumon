/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

/*
 * Simple timed execution of different relevant low-level xnumon operations.
 * Used to understand implications of e.g. caching on performance.
 */

#include "hashes.h"
#include "codesign.h"
#include "cachehash.h"
#include "cachecsig.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>

#ifndef __BSD__
#include <getopt.h>
#endif /* !__BSD__ */

extern int vfs_purge(void);

void
purge(void) {
	if (vfs_purge()) {
		fprintf(stderr, "purge(): %s (%i)\n",
		        strerror(errno), errno);
		exit(EXIT_FAILURE);
	}
}

int hashes_flags;
const char *path;

#define TIMEIT_INIT	clock_t t0, t1
#define TIMEIT_START	t0 = clock()
#define TIMEIT_STOP	t1 = clock()
#define TIMEIT_RESULT	(double)(t1 - t0) / CLOCKS_PER_SEC

double
timeit_hashes(void) {
	TIMEIT_INIT;
	hashes_t hashes;
	off_t size;

	purge();
	TIMEIT_START;
	hashes_path(&size, &hashes, hashes_flags, path);
	TIMEIT_STOP;

	return TIMEIT_RESULT;
}

double
timeit_codesign(void) {
	TIMEIT_INIT;
	codesign_t *cs;

	purge();
	TIMEIT_START;
	cs = codesign_new(path);
	TIMEIT_STOP;
	codesign_free(cs);

	return TIMEIT_RESULT;
}

double
timeit_cachehash_get(void) {
	TIMEIT_INIT;
	hashes_t h;

	bzero(&h, sizeof(hashes_t));
	cachehash_init();
	cachehash_put(0, 0, 0, 0, 0, &h);
	TIMEIT_START;
	cachehash_get(&h, 0, 0, 0, 0, 0);
	TIMEIT_STOP;
	cachehash_fini();

	return TIMEIT_RESULT;
}

double
timeit_cachehash_put(void) {
	TIMEIT_INIT;
	hashes_t h;

	bzero(&h, sizeof(hashes_t));
	cachehash_init();
	TIMEIT_START;
	cachehash_put(0, 0, 0, 0, 0, &h);
	TIMEIT_STOP;
	cachehash_fini();

	return TIMEIT_RESULT;
}

double
timeit_cachecsig_get(void) {
	TIMEIT_INIT;
	hashes_t h;
	codesign_t *cs;

	cs = codesign_new("/usr/bin/iotop");
	memset(&h, 0x7F, sizeof(hashes_t));
	cachecsig_init();
	cachecsig_put(&h, cs);
	codesign_free(cs);
	TIMEIT_START;
	cs = cachecsig_get(&h);
	TIMEIT_STOP;
	cachecsig_fini();

	return TIMEIT_RESULT;
}

double
timeit_cachecsig_put(void) {
	TIMEIT_INIT;
	hashes_t h;
	codesign_t *cs;

	cs = codesign_new("/usr/bin/iotop");
	memset(&h, 0x7F, sizeof(hashes_t));
	cachecsig_init();
	TIMEIT_START;
	cachecsig_put(&h, cs);
	TIMEIT_STOP;
	codesign_free(cs);
	cachecsig_fini();

	return TIMEIT_RESULT;
}

typedef double (*timeit_func)(void);

double
timeit_average(size_t n, timeit_func func) {
	double total = 0.0;
	for (size_t i = 0; i < n; i++) {
		total += func();
	}
	return total / n;
}

static void
fusage(FILE *f, const char *argv0) {
	fprintf(f,
"Usage: %s [-h]\n"
" -h             print usage\n"
, argv0);
}

int
main(int argc, char *argv[]) {
	int ch;
	const char *argv0 = argv[0];

	while ((ch = getopt(argc, argv, "h")) != -1) {
		switch (ch) {
			case 'h':
				fusage(stdout, argv0);
				exit(EXIT_SUCCESS);
			case '?':
				exit(EXIT_FAILURE);
			default:
				fusage(stderr, argv0);
				exit(EXIT_FAILURE);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc > 0) {
		fusage(stderr, argv0);
		exit(EXIT_FAILURE);
	}

	const char *paths[] = {
#if 1
		"/usr/sbin/php-fpm",
#else
		"/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word",
#endif
		"/usr/sbin/coreaudiod",
		"/usr/sbin/mkpassdb",
		"/usr/bin/iotop"
	};

	double avg;

	printf("                    10m       1m     100k      10k\n");
	printf("md5             ");
	for (int i = 0; i < 4; i++) {
		path = paths[i];

		hashes_flags = HASH_MD5;
		avg = timeit_average(10, timeit_hashes);
		printf(" %f", avg);
	}
	printf("\n");

	printf("sha1            ");
	for (int i = 0; i < 4; i++) {
		path = paths[i];

		hashes_flags = HASH_SHA1;
		avg = timeit_average(10, timeit_hashes);
		printf(" %f", avg);
	}
	printf("\n");

	printf("sha256          ");
	for (int i = 0; i < 4; i++) {
		path = paths[i];

		hashes_flags = HASH_SHA256;
		avg = timeit_average(10, timeit_hashes);
		printf(" %f", avg);
	}
	printf("\n");

	printf("md5+sha1        ");
	for (int i = 0; i < 4; i++) {
		path = paths[i];

		hashes_flags = HASH_MD5_SHA1;
		avg = timeit_average(10, timeit_hashes);
		printf(" %f", avg);
	}
	printf("\n");

	printf("sha1+sha256     ");
	for (int i = 0; i < 4; i++) {
		path = paths[i];

		hashes_flags = HASH_SHA1_SHA256;
		avg = timeit_average(10, timeit_hashes);
		printf(" %f", avg);
	}
	printf("\n");

	printf("md5+sha256      ");
	for (int i = 0; i < 4; i++) {
		path = paths[i];

		hashes_flags = HASH_MD5_SHA256;
		avg = timeit_average(10, timeit_hashes);
		printf(" %f", avg);
	}
	printf("\n");

	printf("md5+sha1+sha256 ");
	for (int i = 0; i < 4; i++) {
		path = paths[i];

		hashes_flags = HASH_MD5_SHA1_SHA256;
		avg = timeit_average(10, timeit_hashes);
		printf(" %f", avg);
	}
	printf("\n");

	printf("codesign        ");
	for (int i = 0; i < 4; i++) {
		path = paths[i];

		avg = timeit_average(10, timeit_codesign);
		printf(" %f", avg);
	}
	printf("\n");

	printf("\n");

	printf("cache               get      put\n");
	printf("stat>hash[sz=0] ");
	avg = timeit_average(10, timeit_cachehash_get);
	printf(" %f", avg);
	avg = timeit_average(10, timeit_cachehash_put);
	printf(" %f", avg);
	printf("\n");

	printf("hash>csig[sz=0] ");
	avg = timeit_average(10, timeit_cachecsig_get);
	printf(" %f", avg);
	avg = timeit_average(10, timeit_cachecsig_put);
	printf(" %f", avg);
	printf("\n");


	exit(EXIT_SUCCESS);
}

