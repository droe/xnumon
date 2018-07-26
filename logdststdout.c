/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include "logdststdout.h"

#include "config.h"
#include "attrib.h"

#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <assert.h>

static config_t *config;
static bool do_flush;

static FILE *
logdststdout_open(void) {
	return stdout;
}

static int
logdststdout_close(UNUSED FILE *f) {
	/*
	 * Need to flush if stdout refers to a file in order to prevent
	 * committing incomplete events to disk.  If stdout refers to a TTY,
	 * assume the TTY is line-buffered anyway.
	 */
	if (do_flush)
		fflush(f);
	return 0;
}

static int
logdststdout_init(config_t *cfg) {
	config = cfg;
	do_flush = !isatty(fileno(stdout));
	return 0;
}

static void
logdststdout_fini(void) {
	config = NULL;
}

logdst_t logdststdout = {
	"-", false, true, true, false,
	logdststdout_init,
	NULL,
	logdststdout_fini,
	NULL,
	logdststdout_open,
	logdststdout_close
};

