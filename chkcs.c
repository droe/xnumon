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
 * Code to generate a launchd plist for xnumon, used as part of the build
 * process.  In c because original intent was to make xnumon self-installing.
 */

#include "codesign.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#ifndef __BSD__
#include <getopt.h>
#endif /* !__BSD__ */

static void
fusage(FILE *f, const char *argv0) {
	fprintf(f,
"Usage: %s <path>\n"
"       %s -h\n"
" -h             print usage and exit\n"
, argv0, argv0);
}

int
main(int argc, char *argv[]) {
	int ch;

	while ((ch = getopt(argc, argv, "h")) != -1) {
		switch (ch) {
			case 'h':
				fusage(stdout, argv[0]);
				exit(EXIT_SUCCESS);
			case '?':
				exit(EXIT_FAILURE);
			default:
				fusage(stderr, argv[0]);
				exit(EXIT_FAILURE);
		}
	}
	if (argc != optind + 1) {
		fusage(stderr, argv[0]);
		exit(EXIT_FAILURE);
	}
	argc -= optind;
	argv += optind;

	if (codesign_init() != 0) {
		fprintf(stderr, "Failed to initialize codesign module\n");
		codesign_fini();
		exit(EXIT_FAILURE);
	}

	bool good;
	codesign_t *cs = codesign_new(argv[0]);
	if (!cs) {
		fprintf(stderr, "Failed to acquire code signature!\n");
		exit(EXIT_FAILURE);
	}
	codesign_fprint(stdout, cs);
	good = codesign_is_good(cs);
	codesign_free(cs);

	codesign_fini();

	exit(good ? EXIT_SUCCESS : EXIT_FAILURE);
}

