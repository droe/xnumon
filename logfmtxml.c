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
 * XML log format driver
 */

#include "logfmtxml.h"
#include "logutl.h"

#include "sys.h"

#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

static char *opteol;

static int
logfmtxml_init(config_t *cfg) {
	if (cfg->logoneline) {
		opteol = "";
	} else {
		opteol = "\n";
	}
	return 0;
}

/* double the max indent because lists need two levels in XML */
#define LOGFMTXML_INDENT_MAX (LOGFMT_INDENT_MAX*2)

static bool indent_used[LOGFMTXML_INDENT_MAX+1] = {0};
static char indent[2*LOGFMTXML_INDENT_MAX+1] = {0};
static size_t indent_level = 0;

static void
logfmtxml_indent_inc(void) {
	indent_level++;
	assert(indent_level <= LOGFMTXML_INDENT_MAX);
	indent_used[indent_level] = false;

	if (opteol[0] == '\0')
		return;

	indent[indent_level * 2 - 2] = ' ';
	indent[indent_level * 2 - 1] = ' ';
	indent[indent_level * 2] = '\0';
}

static void
logfmtxml_indent_dec(void) {
	assert(indent_level > 0);
	indent_level--;

	if (opteol[0] == '\0')
		return;

	indent[indent_level * 2] = '\0';
}

static const char *tags[LOGFMTXML_INDENT_MAX+1] = {0};
static size_t tags_next = 0;

static void
logfmtxml_tag_open(FILE *f, const char *label) {
	fprintf(f, "%s<%s>", indent, label);
	tags[tags_next] = label;
	tags_next++;
	assert(tags_next <= LOGFMTXML_INDENT_MAX);
}

static void
logfmtxml_tag_close(FILE *f) {
	assert(tags_next > 0);
	tags_next--;
	fprintf(f, "</%s>%s", tags[tags_next], opteol);
}

static void
logfmtxml_record_begin(FILE *f) {
	fprintf(f, "<event>");
}

static void
logfmtxml_record_end(FILE *f) {
	fprintf(f, "</event>\n");
}

static void
logfmtxml_dict_begin(UNUSED FILE *f) {
	logfmtxml_indent_inc();
}

static void
logfmtxml_dict_end(FILE *f) {
	logfmtxml_indent_dec();
	fprintf(f, "%s", indent);
	if (tags_next > 0)
		logfmtxml_tag_close(f);
}

static void
logfmtxml_dict_item(FILE *f, const char *label) {
	bool first = !indent_used[indent_level];
	if (first) {
		indent_used[indent_level] = true;
		fprintf(f, "%s", opteol);
	}
	logfmtxml_tag_open(f, label);
}

static void
logfmtxml_list_begin(UNUSED FILE *f) {
	logfmtxml_indent_inc();
}

static void
logfmtxml_list_end(FILE *f) {
	logfmtxml_dict_end(f);
}

static void
logfmtxml_list_item(FILE *f, const char *label) {
	logfmtxml_dict_item(f, label);
}

static void
logfmtxml_value_null(FILE *f) {
	logfmtxml_tag_close(f);
}

static void
logfmtxml_value_bool(FILE *f, bool value) {
	fprintf(f, value ? "true" : "false");
	logfmtxml_tag_close(f);
}

static void
logfmtxml_value_int(FILE *f, int64_t value) {
	fprintf(f, "%"PRId64, value);
	logfmtxml_tag_close(f);
}

static void
logfmtxml_value_uint(FILE *f, uint64_t value) {
	fprintf(f, "%"PRIu64, value);
	logfmtxml_tag_close(f);
}

static void
logfmtxml_value_uint_oct(FILE *f, uint64_t value) {
	fprintf(f, "0%"PRIo64, value);
	logfmtxml_tag_close(f);
}

static void
logfmtxml_value_timespec(FILE *f, struct timespec *tv) {
	assert(tv->tv_sec > 0);
	logutl_fwrite_timespec(f, tv);
	logfmtxml_tag_close(f);
}

static void
logfmtxml_value_ttydev(FILE *f, dev_t dev) {
	fprintf(f, "/dev/%s", sys_ttydevname(dev));
	logfmtxml_tag_close(f);
}

static void
logfmtxml_value_buf_hex(FILE *f, const unsigned char *buf, size_t sz) {
	logutl_fwrite_hex(f, buf, sz);
	logfmtxml_tag_close(f);
}

static void
logfmtxml_value_string(FILE *f, const char *s) {
	const unsigned char *p = (const unsigned char *)s;
	size_t sz;
	while (*p != '\0') {
		sz = 0;
		while (p[sz]        && p[sz] != '<' && p[sz] != '>' &&
		       p[sz] != '&' && p[sz] != '"' && p[sz] != '\'')
			sz++;
		if (sz > 0) {
			fwrite(p, sz, 1, f);
			p = p + sz;
		}
		for (;;) {
			if (*p == '<') {
				fprintf(f, "&lt;");
				p++;
			} else if (*p == '>') {
				fprintf(f, "&gt;");
				p++;
			} else if (*p == '&') {
				fprintf(f, "&amp;");
				p++;
			} else if (*p == '"') {
				fprintf(f, "&quot;");
				p++;
			} else if (*p == '\'') {
				fprintf(f, "&apos;");
				p++;
			} else {
				break;
			}
		}
	}
	logfmtxml_tag_close(f);
}

logfmt_t logfmtxml = {
	"xml", true, true,
	logfmtxml_init,
	logfmtxml_record_begin,
	logfmtxml_record_end,
	logfmtxml_dict_begin,
	logfmtxml_dict_end,
	logfmtxml_dict_item,
	logfmtxml_list_begin,
	logfmtxml_list_end,
	logfmtxml_list_item,
	logfmtxml_value_null,
	logfmtxml_value_bool,
	logfmtxml_value_int,
	logfmtxml_value_uint,
	logfmtxml_value_uint_oct,
	logfmtxml_value_timespec,
	logfmtxml_value_ttydev,
	logfmtxml_value_buf_hex,
	logfmtxml_value_string
};

