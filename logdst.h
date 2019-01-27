/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2019, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef LOGDST_H
#define LOGDST_H

#include "attrib.h"
#include "config.h"
#include "logevt.h"

#include <stdbool.h>
#include <stdio.h>

/*
 * There are two different kinds of log destination drivers.  Raw drivers
 * implement ld_event and receive the raw event struct for fully custom
 * logging.  Normal drivers implement ld_open and ld_close for FILE * based
 * formatted logging.  The FILE * produced by ld_open will be passed to the
 * event formatter, which will use the log format driver to write a formatted
 * log record to the FILE *.
 */
typedef int    (*logdst_init_func_t)(config_t *);
typedef int    (*logdst_reinit_func_t)(void);
typedef void   (*logdst_fini_func_t)(void);
typedef FILE * (*logdst_open_func_t)(void);
typedef int    (*logdst_close_func_t)(FILE *);
typedef int    (*logdst_event_func_t)(const logevt_header_t *);
typedef struct {
	const char *ld_name;
	bool ld_raw;                /* wants raw event, not formatted buffer */
	bool ld_oneline;            /* supports compact one-line format */
	bool ld_multiline;          /* supports readable multi-line format */
	bool ld_onelineprefered;    /* prefers oneline if both are available */
	logdst_init_func_t   ld_init;
	logdst_reinit_func_t ld_reinit;
	logdst_fini_func_t   ld_fini;
	logdst_event_func_t  ld_event;  /* raw mode only */
	logdst_open_func_t   ld_open;   /* normal mode only */
	logdst_close_func_t  ld_close;  /* normal mode only */
} logdst_t;


#endif

