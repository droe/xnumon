/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include "kextctl.h"

#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

int
kextctl_load(void) {
	int rv;

	if ((access(XNUMON_DEVPATH, F_OK) == -1) && (errno == ENOENT)) {
		rv = system("/sbin/kextload -q -b " XNUMON_BUNDLEID);
		if (WIFEXITED(rv)) {
			if (WEXITSTATUS(rv) == 0) {
				return 0;
			}
			fprintf(stderr, "kextload " XNUMON_BUNDLEID " "
			                "terminated with exit status %i\n",
			                WEXITSTATUS(rv));
			if (WEXITSTATUS(rv) == 27) {
				/* Starting with High Sierra; see TN 2459 */
				fprintf(stderr, "System policy prevents "
				                "loading the kernel "
				                "extension\n");
			} else if (WEXITSTATUS(rv) == 71) {
				/* Starting with Yosemite */
				fprintf(stderr, "The kext might not be "
				                "installed or SIP prevents "
				                "loading of unsigned kexts\n");
			}
		} else if (WIFSIGNALED(rv)) {
			fprintf(stderr, "kextload terminated by signal %i\n",
			                WTERMSIG(rv));
		} else if (WIFSTOPPED(rv)) {
			fprintf(stderr, "kextload stopped by signal %i\n",
			                WSTOPSIG(rv));
		}
		return -1;
	}
	return 0;
}

int
kextctl_open(void) {
	/* Block SIGTSTP regardless if calling code will catch it or not in
	 * order to avoid the kext waiting for us while we are stopped.
	 * Since SIGSTOP cannot be ignored, the kext still needs to able to
	 * deal with the connected process being stopped. */
	signal(SIGTSTP, SIG_IGN);
	return open(XNUMON_DEVPATH, O_RDONLY);
}

char buf[XNUMON_MSG_MAX];

/*
 * The current implementation passes a static buffer to the caller.
 * This is okay as long as receiving messages from this file descriptor is
 * done by a single thread.
 */
const xnumon_msg_t *
kextctl_recv(int fd) {
	xnumon_msg_t *msg = (xnumon_msg_t *)buf;
	ssize_t n;

	n = read(fd, buf, XNUMON_MSG_HDR);
	if (n < 0) {
		fprintf(stderr, "read() failed: %s (%i)\n",
		                strerror(errno), errno);
		return NULL;
	}
	if (n < (ssize_t)XNUMON_MSG_HDR) {
		fprintf(stderr, "short read (header)\n");
		return NULL;
	}
	if (msg->version != XNUMON_MSG_VERSION) {
		fprintf(stderr, "version mismatch\n");
		return NULL;
	}
	if (msg->msgsz > XNUMON_MSG_MAX) {
		fprintf(stderr, "message too long\n");
		return NULL;
	}
	if (msg->msgsz <= XNUMON_MSG_HDR) {
		fprintf(stderr, "message too short\n");
		return NULL;
	}
	n = read(fd, buf + XNUMON_MSG_HDR, msg->msgsz - XNUMON_MSG_HDR);
	if (n < 0) {
		fprintf(stderr, "read() failed: %s (%i)\n",
		                strerror(errno), errno);
		return NULL;
	}
	if (n + XNUMON_MSG_HDR < msg->msgsz) {
		fprintf(stderr, "short read (body)\n");
		return NULL;
	}
	if (buf[msg->msgsz - 1] != '\0') {
		fprintf(stderr, "path not null-terminated\n");
		return NULL;
	}
	return msg;
}

int
kextctl_ack(int fd, const xnumon_msg_t *msg) {
	int rv;

	assert(msg);
	rv = ioctl(fd, XNUMON_ACK_COOKIE, &msg->cookie);
	if (rv == -1) {
		fprintf(stderr, "ioctl() failed: %s (%i)\n",
		                strerror(errno), errno);
	}
	return rv;
}

int
kextctl_stats(int fd, xnumon_stat_t *st) {
	assert(st);
	return ioctl(fd, XNUMON_GET_STATS, st);
}

void
kextctl_version(FILE *f) {
	fprintf(f, "Kernel extension protocol version: %i\n",
	           XNUMON_MSG_VERSION);
}

