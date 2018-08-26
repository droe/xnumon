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

#include "path.h"
#include "sock.h"

#define SOCKADDR6 "::"
#define SOCKPORT 54345
#define CONNECTADDR6 "2001:db8:c0de::1"
#define CONNECTPORT SOCKPORT

int
server(void) {
	int fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (fd == -1) {
		perror("socket");
		return 1;
	}
	set_so_reuse(fd);

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
	sai.sin6_port = htons(SOCKPORT);
	if (inet_pton(AF_INET6, SOCKADDR6, &sai.sin6_addr) != 1) {
		perror("inet_pton");
		return 1;
	}
	if (bind(fd, (struct sockaddr *)&sai, sizeof(sai)) == -1) {
		perror("bind");
		return 1;
	}
	if (listen(fd, 5) == -1) {
		perror("listen");
		return 1;
	}

	struct fd_set fds;
	FD_ZERO(&fds);
	FD_SET(fd, &fds);
	if (select(fd + 1, &fds, NULL, NULL, NULL) == -1) {
		perror("select");
		return 1;
	}

	bzero(&sai, sizeof(sai));
	socklen_t sailen = sizeof(sai);
	int connfd = accept(fd, (struct sockaddr *)&sai, &sailen);
	if (connfd == -1) {
		perror("accept");
		return 1;
	}
	close(connfd);
	close(fd);
	return 0;
}

int
client(void) {
	int fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (fd == -1) {
		perror("socket");
		return 1;
	}

	struct sockaddr_in6 sai;
	bzero(&sai, sizeof(sai));
	sai.sin6_family = AF_INET6;
	sai.sin6_port = htons(CONNECTPORT);
	if (inet_pton(AF_INET6, CONNECTADDR6, &sai.sin6_addr) != 1) {
		perror("inet_pton");
		return 1;
	}
	if (connect(fd, (struct sockaddr *)&sai, sizeof(sai)) == -1) {
		perror("connect");
		return 1;
	}
	close(fd);
	return 0;
}

int
main(int argc, char *argv[]) {
	pid_t pid;

	printf("spec:testcase returncode=0\n");

	system("sudo ifconfig lo0 inet6 alias "CONNECTADDR6"/128");

	pid = fork();
	if (pid == -1) {
		perror("fork");
		return 1;
	}
	if (pid == 0) {
		sleep(1);
		return client();
	}

	printf("spec:socket-listen subject.pid=%i subject.image.path=%s "
	       "sockaddr="SOCKADDR6" sockport=%i proto=tcp\n",
	       getpid(), getpath(), SOCKPORT);
	printf("spec:socket-accept subject.pid=%i subject.image.path=%s "
	       "peeraddr="CONNECTADDR6" sockport=%i proto=tcp\n",
	       getpid(), getpath(), SOCKPORT);
	printf("spec:socket-connect subject.pid=%i subject.image.path=%s "
	       "peeraddr="CONNECTADDR6" peerport=%i proto=tcp\n",
	       pid, getpath(), CONNECTPORT);
	fflush(stdout);

	int rv = server();
	sleep(1);
	system("sudo ifconfig lo0 inet6 -alias "CONNECTADDR6);
	if (rv != 0) {
		fprintf(stderr, "server failed\n");
		return rv;
	}

	int status;
	waitpid(pid, &status, 0);
	return WEXITSTATUS(status);
}

