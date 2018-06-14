/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include "logdstsyslog.h"

#include "attrib.h"

#include "memstream.h"

#include <stdlib.h>
#include <syslog.h>
#include <assert.h>

static config_t *config;

static char *msg;
static size_t sz;

FILE *
logdstsyslog_open(void) {
	return open_memstream(&msg, &sz);
}

int
logdstsyslog_close(FILE *f) {
	fclose(f);
	if (!msg)
		return -1;
	syslog(LOG_NOTICE, "%s", msg);
	free(msg);
	return 0;
}

int
logdstsyslog_init(config_t *cfg) {
	config = cfg;
	assert(cfg->logoneline);
	setlogmask(LOG_UPTO(LOG_NOTICE));
	openlog("xnumon", LOG_CONS|LOG_PID|LOG_NDELAY, LOG_LOCAL1);
	return 0;
}

void
logdstsyslog_fini(void) {
	closelog();
	config = NULL;
}

