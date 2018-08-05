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
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>

int
main(int argc, char *argv[]) {
	int fd;

	printf("%i\n", getpid());

	system("touch /tmp/test");
	fd = open("/tmp", O_RDONLY);
	if (fd == -1) {
		perror("open");
		return 1;
	}
	if (renameat(fd, "test", fd, "test2") == -1) {
		perror("renameat");
		return 1;
	}
	unlink("/tmp/test2");
	close(fd);

	return 0;
}

