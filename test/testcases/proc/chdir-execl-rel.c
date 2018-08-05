/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#define PATH "/usr/bin/true"
#define ARGV0 "true"
#define CWD "/var/tmp"

int
main(int argc, char *argv[]) {
	char *cwd = realpath(CWD, NULL);

	printf("spec:testcase returncode=0\n");
	printf("spec:image-exec "
	       "subject.pid=%i "
	       "image.path="PATH" "
	       "argv="ARGV0" "
	       "cwd=%s\n",
	       getpid(), cwd);
	fflush(stdout);

	chdir("/");
	chdir("/tmp");
	chdir(CWD);
	/* /private/var/tmp */

	/* child */
	execl("../../.." PATH, ARGV0, (char*)0);
	perror("exec");
	return 1;
}

