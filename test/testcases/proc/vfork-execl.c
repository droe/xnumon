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
#include <sys/types.h>
#include <sys/wait.h>

#include "path.h"

#define PATH "/usr/bin/true"
#define ARGV0 "true"


int
main(int argc, char *argv[]) {
	pid_t pid;

	printf("spec:testcase returncode=0\n");
	fflush(stdout);

	pid = vfork();
	if (pid == -1) {
		perror("vfork");
		return 1;
	} else if (pid == 0) {
		/* child */
		execl(PATH, ARGV0, (char*)0);
		perror("exec");
		_exit(1);
	}

	/* parent */
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

