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

#define ARGV0 "testcases/proc/open-write-self.test"

int
main(int argc, char *argv[]) {
	char buf[1024*16];
	int fd;

	printf("spec:testcase returncode=0\n");
	fflush(stdout);

	fd = open(argv[0], O_RDWR);
	if (fd == -1) {
		perror("open");
		return 1;
	}
	bzero(buf, sizeof(buf));
	if (pwrite(fd, buf, sizeof(buf), 0) == -1) {
		perror("write");
		return 1;
	}
	close(fd);

	printf("spec:image-exec "
	       "subject.pid=%i "
	       "image.path=%s/"ARGV0" "
	       "image.sha256=* "
	       "argv="ARGV0" "
	       "\n",
	       getpid(), getwd(NULL));

	sleep(1);
	unlink(argv[0]);

}

