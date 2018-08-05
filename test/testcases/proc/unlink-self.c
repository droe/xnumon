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

#define ARGV0 "testcases/proc/unlink-self.test"

int
main(int argc, char *argv[]) {
	if (unlink(argv[0]) == -1) {
		perror("unlink");
		return 1;
	}

	printf("spec:image-exec "
	       "subject.pid=%i "
	       "image.path=%s/"ARGV0" "
	       "image.sha256=* "
	       "argv="ARGV0" "
	       "\n",
	       getpid(), getwd(NULL));
	return 0;
}

