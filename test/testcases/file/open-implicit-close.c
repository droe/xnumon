/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int
main(int argc, char *argv[]) {
	int fd;

	printf("spec:testcase returncode=0\n");
	fflush(stdout);

	/* XXX rework to install plist and detect installation */

	fd = open("/tmp/implicit_close", O_RDWR|O_CREAT, 0777);
	if (fd == -1) {
		perror("open");
		return 1;
	}

	/* close(fd); */

	return 0;
}

