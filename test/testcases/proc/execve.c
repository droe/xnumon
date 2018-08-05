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

#define PATH "/usr/bin/true"
#define ARGV0 "true"

int
main(int argc, char *argv[]) {
	printf("spec:testcase returncode=0\n");
	printf("spec:image-exec "
	       "subject.pid=%i "
	       "image.path="PATH" "
	       "argv="ARGV0"\n",
	       getpid());
	fflush(stdout);

	char *cargv[2] = {ARGV0, 0};
	char *cenv[1] = {0};
	execve(PATH, cargv, cenv);
	perror("execve");
	return 1;
}

