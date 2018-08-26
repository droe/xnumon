/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

/*
 * This code was written for use in short-living test case executables and is
 * utterly unfit for any other purposes.
 */

#ifndef TEST_SOCK_H
#define TEST_SOCK_H

#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>

static inline void
set_so_reuse(int fd) {
	int i;

	i = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i)) == -1) {
		perror("setsockopt(SO_REUSEADDR)");
		exit(EXIT_FAILURE);
	}
	i = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &i, sizeof(i)) == -1) {
		perror("setsockopt(SO_REUSEPORT)");
		exit(EXIT_FAILURE);
	}
}

#endif
