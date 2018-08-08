/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
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
	printf("spec:socket-connect subject.pid=%i subject.image.path=%s "
	       "peeraddr="PEERADDR6" peerport=%i proto=tcp\n",
	       getpid(), getpath(), PEERPORT);
	fflush(stdout);

	int fd = 0;
	fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (fd == -1) {
		perror("socket");
		return 1;
	}

	int i = 1;
	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &i, sizeof(i)) == -1) {
		perror("setsockopt(TCP_NODELAY)");
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
		perror("connect");
		return 1;
	}

	/* sleep(1); */
	close(fd);
	return 0;
}

