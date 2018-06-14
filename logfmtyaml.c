/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include "logfmtyaml.h"
#include "logutl.h"

#include "sys.h"

#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

static char indent[2*LOGFMT_INDENT_MAX+1] = {0};
static size_t indent_level = 0;
static bool reuse_line = false;

static int
logfmtyaml_init(UNUSED config_t *cfg) {
	return 0;
}

static void
logfmtyaml_indent_inc(void) {
	indent_level++;
	assert(indent_level <= LOGFMT_INDENT_MAX);
	indent[indent_level * 2 - 2] = ' ';
	indent[indent_level * 2 - 1] = ' ';
	indent[indent_level * 2] = '\0';
}

static void
logfmtyaml_indent_dec(void) {
	assert(indent_level > 0);
	indent_level--;
	indent[indent_level * 2] = '\0';
}

static void
logfmtyaml_record_begin(FILE *f) {
	fprintf(f, "---");
}

static void
logfmtyaml_record_end(FILE *f) {
	fputc('\n', f);
}

static void
logfmtyaml_dict_begin(UNUSED FILE *f) {
	logfmtyaml_indent_inc();
}

static void
logfmtyaml_dict_end(UNUSED FILE *f) {
	logfmtyaml_indent_dec();
}

static void
logfmtyaml_dict_item(FILE *f, const char *label) {
	if (reuse_line) {
		fprintf(f, " %s:", label);
		reuse_line = false;
	} else {
		fprintf(f, "\n%s%s:", indent, label);
	}
}

static void
logfmtyaml_list_begin(UNUSED FILE *f) {
	logfmtyaml_indent_inc();
}

static void
logfmtyaml_list_end(UNUSED FILE *f) {
	logfmtyaml_indent_dec();
}

static void
logfmtyaml_list_item(FILE *f) {
	fprintf(f, "\n%s-", indent);
	reuse_line = true;
}

static void
logfmtyaml_value_null(FILE *f) {
	fprintf(f, " null");
	reuse_line = false;
}

static void
logfmtyaml_value_bool(FILE *f, bool value) {
	fprintf(f, value ? " true" : " false");
	reuse_line = false;
}

static void
logfmtyaml_value_int(FILE *f, int64_t value) {
	fprintf(f, " %"PRId64, value);
	reuse_line = false;
}

static void
logfmtyaml_value_uint(FILE *f, uint64_t value) {
	fprintf(f, " %"PRIu64, value);
	reuse_line = false;
}

static void
logfmtyaml_value_uint_oct(FILE *f, uint64_t value) {
	fprintf(f, " 0o%"PRIo64, value);
	reuse_line = false;
}

static void
logfmtyaml_value_timespec(FILE *f, struct timespec *tv) {
	fputc(' ', f);
	logutl_fwrite_timespec(f, tv);
	reuse_line = false;
}

static void
logfmtyaml_value_ttydev(FILE *f, dev_t dev) {
	fprintf(f, " /dev/%s", sys_ttydevname(dev));
	reuse_line = false;
}

static void
logfmtyaml_value_buf_hex(FILE *f, const unsigned char *buf, size_t sz) {
	fputc(' ', f);
	logutl_fwrite_hex(f, buf, sz);
	reuse_line = false;
}

/*
 * YAML Double-Quoted Style string
 */
static void
logfmtyaml_value_string(FILE *f, const char *s) {
	const char *p = s;
	size_t sz;
	fputc(' ', f);
	fputc('"', f);
	while (*p != '\0') {
		sz = strcspn(p, "\\\"");
		if (sz > 0) {
			fwrite(p, sz, 1, f);
			p = p + sz;
		}
		while (*p == '\\' || *p == '"') {
			fputc('\\', f);
			fputc(*p, f);
			p++;
		}
	}
	fputc('"', f);
	reuse_line = false;
}

logfmt_t logfmtyaml = {
	"yaml", 0, 1,
	logfmtyaml_init,
	logfmtyaml_record_begin,
	logfmtyaml_record_end,
	logfmtyaml_dict_begin,
	logfmtyaml_dict_end,
	logfmtyaml_dict_item,
	logfmtyaml_list_begin,
	logfmtyaml_list_end,
	logfmtyaml_list_item,
	logfmtyaml_value_null,
	logfmtyaml_value_bool,
	logfmtyaml_value_int,
	logfmtyaml_value_uint,
	logfmtyaml_value_uint_oct,
	logfmtyaml_value_timespec,
	logfmtyaml_value_ttydev,
	logfmtyaml_value_buf_hex,
	logfmtyaml_value_string
};

