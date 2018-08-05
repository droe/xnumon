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
#include <unistd.h>
#include <spawn.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "getpath.h"

#define PATH "/usr/bin/true"
#define ARGV0 "true"

int
main(int argc, char *argv[]) {
	int rv;
	pid_t pid;
	char *av[] = {ARGV0, NULL};
	char *ev[] = {NULL};

	printf("spec:testcase returncode=0\n");
	fflush(stdout);

	rv = posix_spawn(&pid, PATH, NULL, NULL, av, ev);
	if (rv == -1) {
		perror("spawn");
		return 1;
	}

	printf("spec:image-exec "
	       "subject.pid=%i "
	       "subject.image.path=%s "
	       "image.path="PATH" "
	       "argv="ARGV0
	       "\n",
	       pid, getpath());

	int status;
	waitpid(pid, &status, 0);
	return WEXITSTATUS(status);
}

