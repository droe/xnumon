/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include "logdstfile.h"

#include "sys.h"
#include "attrib.h"

#include <unistd.h>
#include <fcntl.h>
#include <assert.h>

static config_t *config = NULL;
static FILE *f = NULL;
static gid_t gid;

FILE *
logdstfile_open(void) {
	return f;
}

int
logdstfile_close(FILE *f) {
	fflush(f);
	return 0;
}

int
logdstfile_init(config_t *cfg) {
	config = cfg;
	gid = sys_gidbyname("admin");
	logdstfile_reinit();
	if (!f)
		return -1;
	/* remove incomplete last line, if any */
	for (int offset = -1;; offset--) {
		if (fseek(f, offset, SEEK_END) == -1) {
			fseek(f, 0, SEEK_SET);
			fflush(f);
			ftruncate(fileno(f), ftello(f));
			break;
		}
		if (fgetc(f) == '\n') {
			fflush(f);
			ftruncate(fileno(f), ftello(f));
			break;
		}
	}
#if 0
	/* ensure last log line is terminated */
	if ((fseek(f, -1, SEEK_END) == 0) && (fgetc(f) != '\n'))
		fputc('\n', f);
#endif
	return 0;
}

int
logdstfile_reinit(void) {
	int fd;

	assert(config);
	if (f)
		fclose(f);
	f = fopen(config->logfile, "a+");
	if (!f)
		return -1;
	fd = fileno(f);
	(void)fchown(fd, 0, gid);
	(void)fcntl(fd, F_NOCACHE, 1);
	(void)fcntl(fd, F_SINGLE_WRITER, 1);
	return 0;
}

void
logdstfile_fini(void) {
	if (f)
		fclose(f);
	config = NULL;
}

