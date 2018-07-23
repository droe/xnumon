/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

/*
 * JSON Lines and JSON Seq log format drivers
 */

#include "logfmtjson.h"
#include "logutl.h"

#include "sys.h"

#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

static char *opteol, *optsp;

static bool indent_used[LOGFMT_INDENT_MAX+1] = {0};
static char indent[2*LOGFMT_INDENT_MAX+1] = {0};
static size_t indent_level = 0;

static int
logfmtjson_init(config_t *cfg) {
	if (cfg->logoneline) {
		opteol = "";
		optsp = "";
	} else {
		opteol = "\n";
		optsp = " ";
	}
	return 0;
}

static void
logfmtjson_indent_inc(void) {
	indent_level++;
	assert(indent_level <= LOGFMT_INDENT_MAX);
	indent_used[indent_level] = false;

	if (opteol[0] == '\0')
		return;

	indent[indent_level * 2 - 2] = ' ';
	indent[indent_level * 2 - 1] = ' ';
	indent[indent_level * 2] = '\0';
}

static void
logfmtjson_indent_dec(void) {
	assert(indent_level > 0);
	indent_level--;

	if (opteol[0] == '\0')
		return;

	indent[indent_level * 2] = '\0';
}

static void
logfmtjson_record_begin(UNUSED FILE *f) {
	return;
}

static void
logfmtjsonseq_record_begin(FILE *f) {
	fprintf(f, "\x1E");
}

static void
logfmtjson_record_end(FILE *f) {
	fprintf(f, "\n");
}

static void
logfmtjson_dict_begin(FILE *f) {
	fprintf(f, "{");
	logfmtjson_indent_inc();
}

static void
logfmtjson_dict_end(FILE *f) {
	logfmtjson_indent_dec();
	fprintf(f, "%s%s}", opteol, indent);
}

static void
logfmtjson_dict_item(FILE *f, const char *label) {
	bool first = !indent_used[indent_level];
	if (first)
		indent_used[indent_level] = true;
	fprintf(f, "%s%s%s\"%s\":%s",
	        first ? "" : ",", opteol, indent, label, optsp);
}

static void
logfmtjson_list_begin(FILE *f) {
	fprintf(f, "[");
	logfmtjson_indent_inc();
}

static void
logfmtjson_list_end(FILE *f) {
	logfmtjson_indent_dec();
	fprintf(f, "%s%s]", opteol, indent);
}

static void
logfmtjson_list_item(FILE *f) {
	bool first = !indent_used[indent_level];
	if (first)
		indent_used[indent_level] = true;
	fprintf(f, "%s%s%s", first ? "" : ",", opteol, indent);
}

static void
logfmtjson_value_null(FILE *f) {
	fprintf(f, "null");
}

static void
logfmtjson_value_bool(FILE *f, bool value) {
	fprintf(f, value ? "true" : "false");
}

static void
logfmtjson_value_int(FILE *f, int64_t value) {
	fprintf(f, "%"PRId64, value);
}

static void
logfmtjson_value_uint(FILE *f, uint64_t value) {
	fprintf(f, "%"PRIu64, value);
}

static void
logfmtjson_value_uint_oct(FILE *f, uint64_t value) {
	fprintf(f, "\"0%"PRIo64"\"", value);
}

static void
logfmtjson_value_timespec(FILE *f, struct timespec *tv) {
	assert(tv->tv_sec > 0);
	fprintf(f, "\"");
	logutl_fwrite_timespec(f, tv);
	fprintf(f, "\"");
}

static void
logfmtjson_value_ttydev(FILE *f, dev_t dev) {
	fprintf(f, "\"/dev/%s\"", sys_ttydevname(dev));
}

static void
logfmtjson_value_buf_hex(FILE *f, const unsigned char *buf, size_t sz) {
	fprintf(f, "\"");
	logutl_fwrite_hex(f, buf, sz);
	fprintf(f, "\"");
}

static void
logfmtjson_value_string(FILE *f, const char *s) {
	const unsigned char *p = (const unsigned char *)s;
	size_t sz;
	fputc('"', f);
	while (*p != '\0') {
		sz = 0;
		while (p[sz] >= 0x20 && p[sz] != '"' && p[sz] != '\\')
			sz++;
		if (sz > 0) {
			fwrite(p, sz, 1, f);
			p = p + sz;
		}
		for (;;) {
			if (*p == '"'  || *p == '\\') {
				fputc('\\', f);
				fputc(*p, f);
				p++;
			} else if (*p == '\b') {
				fprintf(f, "\\b");
				p++;
			} else if (*p == '\f') {
				fprintf(f, "\\f");
				p++;
			} else if (*p == '\n') {
				fprintf(f, "\\n");
				p++;
			} else if (*p == '\r') {
				fprintf(f, "\\r");
				p++;
			} else if (*p == '\t') {
				fprintf(f, "\\t");
				p++;
			} else if (*p > 0 && *p < 0x20) {
				fprintf(f, "\\u00%02X", *p);
				p++;
			} else {
				break;
			}
		}
	}
	fputc('"', f);
}

logfmt_t logfmtjson = {
	"json", true, true,
	logfmtjson_init,
	logfmtjson_record_begin,
	logfmtjson_record_end,
	logfmtjson_dict_begin,
	logfmtjson_dict_end,
	logfmtjson_dict_item,
	logfmtjson_list_begin,
	logfmtjson_list_end,
	logfmtjson_list_item,
	logfmtjson_value_null,
	logfmtjson_value_bool,
	logfmtjson_value_int,
	logfmtjson_value_uint,
	logfmtjson_value_uint_oct,
	logfmtjson_value_timespec,
	logfmtjson_value_ttydev,
	logfmtjson_value_buf_hex,
	logfmtjson_value_string
};

logfmt_t logfmtjsonseq = {
	"json-seq", true, true,
	logfmtjson_init,
	logfmtjsonseq_record_begin,
	logfmtjson_record_end,
	logfmtjson_dict_begin,
	logfmtjson_dict_end,
	logfmtjson_dict_item,
	logfmtjson_list_begin,
	logfmtjson_list_end,
	logfmtjson_list_item,
	logfmtjson_value_null,
	logfmtjson_value_bool,
	logfmtjson_value_int,
	logfmtjson_value_uint,
	logfmtjson_value_uint_oct,
	logfmtjson_value_timespec,
	logfmtjson_value_ttydev,
	logfmtjson_value_buf_hex,
	logfmtjson_value_string
};

