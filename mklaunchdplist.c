/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2019, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

/*
 * Code to generate a launchd plist for xnumon, used as part of the build
 * process.  In c because original intent was to make xnumon self-installing.
 */

#include "launchd.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#ifndef __BSD__
#include <getopt.h>
#endif /* !__BSD__ */

static void
fusage(FILE *f, const char *argv0) {
	fprintf(f,
"Usage: %s -l label -d targetdir -e execpath -- [xnumon options]\n"
"       %s -h\n"
" -l label       basename of plist, usually reverse DNS ID\n"
" -d targetdir   target directory to write plist file into\n"
" -e execpath    path to the xnumon binary to be launched by the plist\n"
" -h             print usage and exit\n"
, argv0, argv0);
}

int
main(int argc, char *argv[]) {
	int ch;
	char *label = NULL;
	char *targetdir = NULL;
	char *execpath = NULL;

	while ((ch = getopt(argc, argv, "l:d:e:h")) != -1) {
		switch (ch) {
			case 'l':
				label = strdup(optarg);
				break;
			case 'd':
				targetdir = strdup(optarg);
				break;
			case 'e':
				execpath = strdup(optarg);
				break;
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
	if (!label || !targetdir || !execpath) {
		fusage(stderr, argv[0]);
		exit(EXIT_FAILURE);
	}
	argc -= optind;
	argv += optind;

	int ac = argc + 1;
	char **av = malloc(ac * sizeof(char *));
	av[0] = strdup(execpath);
	for (int i = 1; i < ac; i++)
		av[i] = strdup(argv[i-1]);
	launchd_plist_write(label, targetdir, execpath, ac, av);
	for (int i = 0; i < ac; i++)
		free(av[i]);
	free(av);
	free(label);
	free(targetdir);
	free(execpath);
	exit(EXIT_SUCCESS);
}

