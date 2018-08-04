/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef CONFIG_H
#define CONFIG_H

#include "hashes.h"
#include "strset.h"
#include "attrib.h"

#include <stddef.h>

typedef struct {
	char *path;
	char *id;

	bool launchd_mode;      /* only settable via command line */
	bool debug;

	size_t stats_interval;  /* generate xnumon-stats every n seconds */
	size_t limit_nofile;
	int events;             /* bit mask of enabled events */

	int kextlevel;
#define KEXTLEVEL_NONE 0
#define KEXTLEVEL_OPEN 1
#define KEXTLEVEL_HASH 2
#define KEXTLEVEL_CSIG 3
	int hflags;
	/* HASH_* see hashes.h */
	int envlevel;
#define ENVLEVEL_NONE 0
#define ENVLEVEL_DYLD 1
#define ENVLEVEL_FULL 2
	bool codesign;
	bool resolve_users_groups;

	bool omit_mode;
	bool omit_size;
	bool omit_mtime;
	bool omit_ctime;
	bool omit_btime;
	bool omit_groups;
	bool omit_sid;
	bool omit_apple_hashes;
	size_t ancestors;       /* 0 unlimited, > 0 limited */

	int logdst;
	int logfmt;
	int logoneline;         /* compact one-line log format */
	char *logfile;

	bool suppress_image_exec_at_start;
	strset_t suppress_image_exec_by_ident;
	strset_t suppress_image_exec_by_path;
	strset_t suppress_image_exec_by_ancestor_ident;
	strset_t suppress_image_exec_by_ancestor_path;
	strset_t suppress_process_access_by_subject_ident;
	strset_t suppress_process_access_by_subject_path;
	bool suppress_socket_op_localhost;
	strset_t suppress_socket_op_by_subject_ident;
	strset_t suppress_socket_op_by_subject_path;
} config_t;

config_t * config_new(const char *) MALLOC;
void config_free(config_t *) NONNULL(1);

int config_str(config_t *, const char *, const char *) NONNULL(1,2,3) WUNRES;

int config_kextlevel(config_t *, const char *) NONNULL(1,2);
const char * config_kextlevel_s(config_t *) NONNULL(1);
int config_envlevel(config_t *, const char *) NONNULL(1,2);
const char * config_envlevel_s(config_t *) NONNULL(1);

char * config_events_s(config_t *) NONNULL(1);

#endif

