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
#include <fcntl.h>

#include "getpath.h"

/*
 * connect(2) from non-blocking socket, triggers radar 43006946
 */

int
main(int argc, char *argv[]) {
	printf("spec:testcase returncode=0\n");
	printf("spec:radar43006946:socket-connect "
	       "subject.pid=%i subject.image.path=%s "
	       "peeraddr="PEERADDR4" peerport=%i proto=tcp\n",
	       getpid(), getpath(), PEERPORT);
	fflush(stdout);

	int fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (fd == -1) {
		perror("socket");
		return 1;
	}

	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		perror("fcntl(F_GETFL)");
		return 1;
	}
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
		perror("fcntl(F_SETFL)");
		return 1;
	}

	struct sockaddr_in6 sai;
	bzero(&sai, sizeof(sai));
	sai.sin6_family = AF_INET6;
	sai.sin6_port = htons(PEERPORT);
	if (inet_pton(AF_INET6, PEERADDR4, &sai.sin6_addr) != 1) {
		perror("inet_pton");
		return 1;
	}
	if (connect(fd, (struct sockaddr *)&sai, sizeof(sai)) == -1) {
		if (errno != EINPROGRESS) {
			perror("connect");
			return 1;
		}

		struct fd_set fds;
		FD_ZERO(&fds);
		FD_SET(fd, &fds);
		if (select(fd + 1, NULL, &fds, NULL, NULL) == -1) {
			perror("select");
			return 1;
		}

		int err;
		socklen_t errl = sizeof(err);
		if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errl) == -1) {
			perror("getsockopt(SOL_SOCKET, SO_ERROR)");
			return 1;
		}
		if (err != 0) {
			perror("connect");
			return 1;
		}
	}

	/* sleep(1); */
	close(fd);
	return 0;
}

