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
#include <errno.h>

#include <sys/types.h>
#include <sys/ptrace.h>

#include "path.h"

int
main(int argc, char *argv[]) {
	printf("spec:testcase returncode=0\n");
	fflush(stdout);

	printf("spec:absent:process-access "
	       "subject.pid=%i "
	       "\n",
	       getpid());

	if (ptrace(PT_DENY_ATTACH, 0, NULL, 0) == -1) {
		perror("ptrace(PT_DENY_ATTACH)");
		return 1;
	}
	return 0;
}

