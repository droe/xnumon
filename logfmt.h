/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef LOGFMT_H
#define LOGFMT_H

#include "attrib.h"
#include "config.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#define LOGFMT_INDENT_MAX 5

typedef int (*logfmt_init_func_t)(config_t *);
typedef void (*logfmt_noarg_func_t)(FILE *);
typedef void (*logfmt_bool_func_t)(FILE *, bool);
typedef void (*logfmt_int_func_t)(FILE *, int64_t);
typedef void (*logfmt_uint_func_t)(FILE *, uint64_t);
typedef void (*logfmt_timespec_func_t)(FILE *, struct timespec *);
typedef void (*logfmt_ttydev_func_t)(FILE *, dev_t);
typedef void (*logfmt_buf_func_t)(FILE *, const unsigned char *, size_t);
typedef void (*logfmt_cchar_func_t)(FILE *, const char *);

typedef struct {
	/* meta information */
	const char *lf_name;
	bool lf_oneline;                /* supports compact */
	bool lf_multiline;              /* supports multi-line */
	logfmt_init_func_t lf_init;

	/* actual render functions */
	logfmt_noarg_func_t     record_begin;
	logfmt_noarg_func_t     record_end;
	logfmt_noarg_func_t     dict_begin;
	logfmt_noarg_func_t     dict_end;
	logfmt_cchar_func_t     dict_item;
	logfmt_noarg_func_t     list_begin;
	logfmt_noarg_func_t     list_end;
	logfmt_noarg_func_t     list_item;
	logfmt_noarg_func_t     value_null;
	logfmt_bool_func_t      value_bool;
	logfmt_int_func_t       value_int;
	logfmt_uint_func_t      value_uint;
	logfmt_uint_func_t      value_uint_oct;
	logfmt_timespec_func_t  value_timespec;
	logfmt_ttydev_func_t    value_ttydev;
	logfmt_buf_func_t       value_buf_hex;
	logfmt_cchar_func_t     value_string;
} logfmt_t;

#endif

