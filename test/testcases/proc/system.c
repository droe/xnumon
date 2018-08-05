/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "getpath.h"

#define PATH "/usr/bin/true"

int
main(int argc, char *argv[]) {
	int rv;

	printf("spec:testcase returncode=0\n");
	fflush(stdout);

	rv = system(PATH);
	if (rv == -1) {
		perror("system");
		return 1;
	}

	printf("spec:image-exec "
	       "subject.image.path=%s "
	       "image.path=/bin/sh "
	       "\n", getpath());
	printf("spec:image-exec "
	       "subject.image.path=/bin/sh "
	       "image.path="PATH" "
	       "argv="PATH
	       "\n");

	return rv;
}

