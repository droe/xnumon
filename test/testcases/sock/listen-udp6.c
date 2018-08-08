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

#define SOCKADDR6 "::"
#define SOCKPORT 54345

int
main(int argc, char *argv[]) {
	printf("spec:testcase returncode=0\n");
	printf("spec:socket-listen subject.pid=%i subject.image.path=%s "
	       "sockaddr="SOCKADDR6" sockport=%i proto=udp\n",
	       getpid(), getpath(), SOCKPORT);
	fflush(stdout);

	int fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd == -1) {
		perror("socket");
		return 1;
	}

	struct sockaddr_in6 sai;
	bzero(&sai, sizeof(sai));
	sai.sin6_family = AF_INET6;
	sai.sin6_port = htons(SOCKPORT);
	if (inet_pton(AF_INET6, SOCKADDR6, &sai.sin6_addr) != 1) {
		perror("inet_pton");
		return 1;
	}
	if (bind(fd, (struct sockaddr *)&sai, sizeof(sai)) == -1) {
		perror("bind");
		return 1;
	}

	/* sleep(1); */
	close(fd);
	return 0;
}

