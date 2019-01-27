/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2019, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include "logdstsyslog.h"

#include "config.h"
#include "attrib.h"

#include "memstream.h"

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <assert.h>

static config_t *config;

static char *msg;
static size_t sz;

static FILE *
logdstsyslog_open(void) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunguarded-availability"
	return open_memstream(&msg, &sz);
#pragma clang diagnostic pop
}

static int
logdstsyslog_close(FILE *f) {
	fclose(f);
	if (!msg)
		return -1;
	syslog(LOG_NOTICE, "%s", msg);
	free(msg);
	return 0;
}

static int
logdstsyslog_init(config_t *cfg) {
	config = cfg;
	assert(cfg->logoneline);
	setlogmask(LOG_UPTO(LOG_NOTICE));
	openlog("xnumon", LOG_CONS|LOG_PID|LOG_NDELAY, LOG_LOCAL1);
	return 0;
}

static void
logdstsyslog_fini(void) {
	closelog();
	config = NULL;
}

logdst_t logdstsyslog = {
	"syslog", false, true, false, true,
	logdstsyslog_init,
	NULL,
	logdstsyslog_fini,
	NULL,
	logdstsyslog_open,
	logdstsyslog_close
};

