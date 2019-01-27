/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2019, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include "aupipe.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>

#include <bsm/libbsm.h>
#include <security/audit/audit_ioctl.h>

static int
aupipe_config(int fd, unsigned int classmask) {
	int i;
	unsigned int ui;

	i = AUDITPIPE_PRESELECT_MODE_LOCAL;
	if (ioctl(fd, AUDITPIPE_SET_PRESELECT_MODE, &i) == -1) {
		fprintf(stderr, "ioctl(AUDITPIPE_SET_PRESELECT_MODE, "
		                "AUDITPIPE_PRESELECT_MODE_LOCAL): "
		                "%s (%i)\n",
		                strerror(errno), errno);
		return -1;
	}

	if (ioctl(fd, AUDITPIPE_GET_QLIMIT_MAX, &i) == -1) {
		fprintf(stderr, "ioctl(AUDITPIPE_GET_QLIMIT_MAX): "
		                "%s (%i)\n",
		                strerror(errno), errno);
		return -1;
	}

	if (ioctl(fd, AUDITPIPE_SET_QLIMIT, &i) == -1) {
			fprintf(stderr, "ioctl(AUDITPIPE_SET_QLIMIT, %i): "
			                "%s (%i)\n",
			                i, strerror(errno), errno);
		return -1;
	}

	ui = classmask;
	if (ioctl(fd, AUDITPIPE_SET_PRESELECT_FLAGS, &ui) == -1) {
		fprintf(stderr, "ioctl(AUDITPIPE_SET_PRESELECT_FLAGS, "
		                "0x%08x): %s (%i)\n",
		                ui, strerror(errno), errno);
		return -1;
	}

	ui = classmask;
	if (ioctl(fd, AUDITPIPE_SET_PRESELECT_NAFLAGS, &ui) == -1) {
		fprintf(stderr, "ioctl(AUDITPIPE_SET_PRESELECT_NAFLAGS, "
		                "0x%08x): %s (%i)\n",
		                 ui, strerror(errno), errno);
		return -1;
	}

	if (ioctl(fd, AUDITPIPE_FLUSH) == -1) {
		fprintf(stderr, "ioctl(AUDITPIPE_FLUSH): %s (%i)\n",
		                strerror(errno), errno);
		return -1;
	}

	return 0;
}

FILE *
aupipe_fopen(unsigned int classmask) {
	FILE *f;
	int fd;

	if ((f = fopen("/dev/auditpipe", "r")) == NULL) {
		fprintf(stderr, "fopen(/dev/auditpipe): %s (%i)\n",
		                strerror(errno), errno);
		return NULL;
	}

	if ((fd = fileno(f)) == -1) {
		fprintf(stderr, "fileno(f): %s (%i)\n",
		                strerror(errno), errno);
		return NULL;
	}

	if (aupipe_config(fd, classmask) == -1) {
		fclose(f);
		return NULL;
	}

	return f;
}

int
aupipe_open(unsigned int classmask) {
	int fd;

	if ((fd = open("/dev/auditpipe", O_RDONLY)) == -1) {
		fprintf(stderr, "open(/dev/auditpipe): %s (%i)\n",
		                strerror(errno), errno);
		return -1;
	}

	if (aupipe_config(fd, classmask) == -1) {
		close(fd);
		return -1;
	}

	return fd;
}

void
aupipe_stats(int fd, aupipe_stat_t *st) {
	if (ioctl(fd, AUDITPIPE_GET_QLEN, &st->qlen) == -1) {
		st->qlen = 0;
	}
	if (ioctl(fd, AUDITPIPE_GET_QLIMIT, &st->qlimit) == -1) {
		st->qlimit = 0;
	}
	if (ioctl(fd, AUDITPIPE_GET_INSERTS, &st->inserts) == -1) {
		st->inserts = 0;
	}
	if (ioctl(fd, AUDITPIPE_GET_READS, &st->reads) == -1) {
		st->reads = 0;
	}
	if (ioctl(fd, AUDITPIPE_GET_DROPS, &st->drops) == -1) {
		st->drops = 0;
	}
}

