/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>

#include "getpath.h"

int
main(int argc, char *argv[]) {
	printf("spec:testcase returncode=0\n");
	printf("spec:socket-listen subject.pid=%i subject.image.path=%s "
	       "proto=raw\n",
	       getpid(), getpath());
	fflush(stdout);

	int fd = socket(AF_INET, SOCK_RAW, 0);
	if (fd == -1) {
		perror("socket");
		return 1;
	}

	/* sleep(1); */
	close(fd);
	return 0;
}

