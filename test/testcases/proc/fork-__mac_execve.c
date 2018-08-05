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

#define __APPLE_API_PRIVATE
#include <security/mac.h>
#undef __APPLE_API_PRIVATE

#include "getpath.h"

#define PATH "/usr/bin/true"
#define ARGV0 "true"

int
main(int argc, char *argv[]) {
	pid_t pid;

	printf("spec:testcase returncode=0\n");
	fflush(stdout);

	pid = fork();
	if (pid == -1) {
		perror("fork");
		return 1;
	} else if (pid == 0) {
		/* child */
		char *cargv[2] = {ARGV0, 0};
		__mac_execve(PATH, cargv, NULL, NULL);
		perror("__mac_execve");
		return 1;
	}

	/* parent */
	printf("spec:image-exec "
	       "subject.pid=%i "
	       "subject.image.path=%s "
	       "image.path="PATH" "
	       "argv="ARGV0  // __mac_execve() seems to not have argv (!)
	       "\n",
	       pid, getpath());
	return 0;
}

