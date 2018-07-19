/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include "config.h"

#include "log.h"
#include "cf.h"
#include "sys.h"
#include "memstream.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include <CoreFoundation/CoreFoundation.h>

#define CFGDIR          "/Library/Application Support/ch.roe.xnumon"
#define CFG_LOCAL       CFGDIR "/configuration.plist"
#define CFG_DIST        CFGDIR "/configuration.plist-default"

/*
 * Decide which of the configuration files at path1 (manual override),
 * path2 (local configuration) or path3 (default config installed by pkg) to
 * select for configuration loading.
 */
static const char *
select_file(const char *path1, const char *path2, const char *path3) {
	/* path1 is the override path, may be NULL, if != NULL must exist */
	if (path1) {
		if (access(path1, R_OK) == 0)
			return path1;
		else
			return NULL;
	}
	/* path2 is the local config file, missing is ok, read failure not */
	if ((access(path2, R_OK) == 0) || (errno != ENOENT))
		return path2;
	/* path3 is the default config, should not be missing */
	return path3;
}

/*
 * Parse a string of comma-separated eventcodes into a bitmask of events.
 */
static int
config_parse_events(const char *spec) {
	const char *p;
	size_t sz;
	int flags;
	int i;

	flags = 0;
	p = spec;
	for (;;) {
		sz = 0;
		while ((p[sz] != '\0') && (p[sz] != ',') && (p[sz] != ' '))
			sz++;
		if (sz == 1 && !memcmp(p, "0", sz))
			flags |= LOGEVT_FLAG(LOGEVT_XNUMON_OPS);
		else {
			i = atoi(p);
			if (i == 0 || i > LOGEVT_SIZE)
				return -1;
			flags |= LOGEVT_FLAG(i);
		}
		if (!p[sz])
			break;
		p += sz + 1;
		while ((p[sz] != '\0') && (p[sz] == ' '))
			sz++;
	}
	if (flags == 0)
		return -1;
	return flags;
}

char *
config_events_s(config_t *cfg) {
	int i = cfg->events;
	int code = 0;

	char *msg;
	size_t sz;
	FILE *f;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunguarded-availability"
	f = open_memstream(&msg, &sz);
#pragma clang diagnostic pop
	if (!f)
		return NULL;

	if (i & 1) {
		fprintf(f, "%i", code);
	}
	for (;;) {
		i >>= 1;
		code++;
		if (i == 0)
			break;
		else if (i & 1) {
			fprintf(f, ",%i", code);
		}
	}
	fclose(f);
	if (!msg)
		return NULL;
	return msg;
}

static int
config_set_bool(bool *b, const char *value) {
	if (!strcmp(value, "true")
	 || !strcmp(value, "yes")
	 || !strcmp(value, "y")
	 || !strcmp(value, "1")) {
		*b = true;
		return 0;
	}
	if (!strcmp(value, "false")
	 || !strcmp(value, "no")
	 || !strcmp(value, "n")
	 || !strcmp(value, "0")) {
		*b = false;
		return 0;
	}
	return -1;
}

/*
 * Central simple typed configuration option processing function for both
 * config file and command line overrides.  Arrays are processed separately
 * and cannot be overridden on the command line.
 */
int
config_str(config_t *cfg, const char *key, const char *value) {
	fprintf(stderr, "\t%-23s %s\n", key, value);

	/*
	 * Consecutive strcmp has bad runtime complexity, but since we're only
	 * loading the configuration once it's not worth optimizing right now.
	 */

	if (!strcmp(key, "config_id")) {
		cfg->id = strdup(value);
		return cfg->id == NULL ? -1 : 0;
	}

	if (!strcmp(key, "rlimit_nofile")) {
		cfg->limit_nofile = atoi(value);
		return 0;
	}

	if (!strcmp(key, "events")) {
		cfg->events = config_parse_events(value);
		return cfg->events == -1 ? -1 : 0;
	}

	if (!strcmp(key, "stats_interval")) {
		cfg->stats_interval = atoi(value);
		return 0;
	}

	if (!strcmp(key, "kextlevel"))
		return config_kextlevel(cfg, value);

	if (!strcmp(key, "hashes")) {
		cfg->hflags = hashes_parse(value);
		return cfg->hflags == -1 ? -1 : 0;
	}

	if (!strcmp(key, "codesign")) {
		if (config_set_bool(&cfg->codesign, value) == -1)
			return -1;
		return 0;
	}

	if (!strcmp(key, "resolve_users_groups")) {
		if (config_set_bool(&cfg->resolve_users_groups, value) == -1)
			return -1;
		return 0;
	}

	if (!strcmp(key, "omit_mode")) {
		if (config_set_bool(&cfg->omit_mode, value) == -1)
			return -1;
		return 0;
	}

	if (!strcmp(key, "omit_size")) {
		if (config_set_bool(&cfg->omit_size, value) == -1)
			return -1;
		return 0;
	}

	if (!strcmp(key, "omit_mtime")) {
		if (config_set_bool(&cfg->omit_mtime, value) == -1)
			return -1;
		return 0;
	}

	if (!strcmp(key, "omit_ctime")) {
		if (config_set_bool(&cfg->omit_ctime, value) == -1)
			return -1;
		return 0;
	}

	if (!strcmp(key, "omit_btime")) {
		if (config_set_bool(&cfg->omit_btime, value) == -1)
			return -1;
		return 0;
	}

	if (!strcmp(key, "omit_groups")) {
		if (config_set_bool(&cfg->omit_groups, value) == -1)
			return -1;
		return 0;
	}

	if (!strcmp(key, "omit_apple_hashes")) {
		if (config_set_bool(&cfg->omit_apple_hashes, value) == -1)
			return -1;
		return 0;
	}

	if (!strcmp(key, "ancestors")) {
		if (!strcmp(value, "unlimited"))
			cfg->ancestors = SIZE_MAX;
		else
			cfg->ancestors = atoi(value);
		return 0;
	}

	if (!strcmp(key, "debug")) {
		if (config_set_bool(&cfg->debug, value) == -1)
			return -1;
		return 0;
	}

	if (!strcmp(key, "log_format")) {
		if (logfmt_parse(cfg, value) == -1)
			return -1;
		return 0;
	}

	if (!strcmp(key, "log_destination")) {
		if (logdst_parse(cfg, value) == -1)
			return -1;
		return 0;
	}

	if (!strcmp(key, "log_mode")) {
		if (!strcmp(value, "oneline"))
			cfg->logoneline = 1;
		else if (!strcmp(value, "multiline"))
			cfg->logoneline = 0;
		else
			return -1;
		return 0;
	}

	if (!strcmp(key, "suppress_image_exec_at_start")) {
		if (config_set_bool(&cfg->suppress_image_exec_at_start,
		                    value) == -1)
			return -1;
		return 0;
	}

	return -1;
}

static int
config_str_from_plist(config_t *cfg, const char *optname,
                      CFPropertyListRef plist, CFStringRef key) {
	CFStringRef cfs;
	int rv;
	char *s;

	cfs = CFDictionaryGetValue((CFDictionaryRef)plist, key);
	if (!cfs)
		return 0;
	if (!cf_is_string(cfs))
		return -1;

	s = cf_cstr(cfs);
	if (!s)
		return -1;
	rv = config_str(cfg, optname, s);
	free(s);
	if (rv == -1)
		return -1;
	return 0;
}

static int
config_bool_from_plist(config_t *cfg, const char *optname,
                       CFPropertyListRef plist, CFStringRef key) {
	CFBooleanRef cfb;
	int rv;

	cfb = CFDictionaryGetValue((CFDictionaryRef)plist, key);
	if (!cfb)
		return 0;
	if (!cf_is_boolean(cfb))
		return -1;

	if (CFBooleanGetValue(cfb))
		rv = config_str(cfg, optname, "true");
	else
		rv = config_str(cfg, optname, "false");
	if (rv == -1)
		return -1;
	return 0;
}

static int
config_strset_from_plist(strset_t *set,
                         CFPropertyListRef plist, CFStringRef key) {
	CFArrayRef arr;
	CFIndex arrsz;
	char **v;

	if (!plist)
		return strset_init(set, 0, NULL);
	arr = CFDictionaryGetValue((CFDictionaryRef)plist, key);
	if (!arr || !cf_is_array(arr))
		return strset_init(set, 0, NULL);
	arrsz = CFArrayGetCount(arr);
	if (arrsz == 0)
		return strset_init(set, 0, NULL);
	v = cf_cstrv(arr);
	if (!v)
		return -1;
	return strset_init(set, arrsz, v);
}

#define CONFIG_STR_FROM_PLIST(RV, CFG, PLIST, KEY) \
	if ((RV = config_str_from_plist(CFG, KEY, PLIST, CFSTR(KEY))) == -1) { \
		fprintf(stderr, "Failed to load '" KEY "'\n"); \
		goto errout; \
	}
#define CONFIG_BOOL_FROM_PLIST(RV, CFG, PLIST, KEY) \
	if ((RV = config_bool_from_plist(CFG, KEY, PLIST, CFSTR(KEY))) == -1) {\
		fprintf(stderr, "Failed to load '" KEY "'\n"); \
		goto errout; \
	}
#define CONFIG_STRSET_FROM_PLIST(RV, CFG, PLIST, KEY) \
	if ((rv = config_strset_from_plist(&CFG->KEY, PLIST, \
	                                   CFSTR(#KEY))) == -1) { \
		fprintf(stderr, "Failed to load " #KEY "\n"); \
		goto errout; \
	}

config_t *
config_new(const char *cfgpath) {
	const char *selected_path;
	char *wd;
	CFPropertyListRef plist = NULL;
	config_t *cfg;
	int rv;

	cfg = malloc(sizeof(config_t));
	if (!cfg)
		return NULL;
	bzero(cfg, sizeof(config_t));

	/* set defaults that differ from all zeroes */
	cfg->limit_nofile = 8192;
	cfg->events = (1 << LOGEVT_SIZE) - 1;
	cfg->stats_interval = 3600;
	cfg->kextlevel = KEXTLEVEL_HASH;
	cfg->hflags = HASH_SHA256;
	cfg->codesign = true;
	cfg->resolve_users_groups = true;
	cfg->omit_apple_hashes = true;
	cfg->ancestors = SIZE_MAX;
	cfg->logoneline = -1; /* any */
	cfg->suppress_image_exec_at_start = true;
	if (logfmt_parse(cfg, "json") == -1) {
		fprintf(stderr, "Failed to set default logfmt 'json'\n");
		goto errout;
	}
	if (logdst_parse(cfg, "-") == -1) {
		fprintf(stderr, "Failed to set default logdst '-'\n");
		goto errout;
	}

	/* load configuration plist */
	selected_path = select_file(cfgpath, CFG_LOCAL, CFG_DIST);
	plist = cf_plist_load(selected_path);
	if (!plist) {
		fprintf(stderr, "Failed to load config file!\n");
		goto errout;
	}
	assert(selected_path);
	wd = getcwd(NULL, 0);
	if (!wd) {
		fprintf(stderr, "Out of memory!\n");
		goto errout;
	}
	cfg->path = sys_realpath(selected_path, wd);
	free(wd);
	if (!cfg->path) {
		fprintf(stderr, "Out of memory!\n");
		goto errout;
	}

	/* String configuration items cannot handle plist==NULL */
	CONFIG_STR_FROM_PLIST(rv, cfg, plist, "config_id");
	CONFIG_STR_FROM_PLIST(rv, cfg, plist, "log_format");
	CONFIG_STR_FROM_PLIST(rv, cfg, plist, "log_destination");
	CONFIG_STR_FROM_PLIST(rv, cfg, plist, "log_mode");
	CONFIG_STR_FROM_PLIST(rv, cfg, plist, "kextlevel");
	CONFIG_STR_FROM_PLIST(rv, cfg, plist, "hashes");
	CONFIG_BOOL_FROM_PLIST(rv, cfg, plist, "codesign");
	CONFIG_BOOL_FROM_PLIST(rv, cfg, plist, "resolve_users_groups");
	CONFIG_BOOL_FROM_PLIST(rv, cfg, plist, "omit_mode");
	CONFIG_BOOL_FROM_PLIST(rv, cfg, plist, "omit_size");
	CONFIG_BOOL_FROM_PLIST(rv, cfg, plist, "omit_mtime");
	CONFIG_BOOL_FROM_PLIST(rv, cfg, plist, "omit_ctime");
	CONFIG_BOOL_FROM_PLIST(rv, cfg, plist, "omit_btime");
	CONFIG_BOOL_FROM_PLIST(rv, cfg, plist, "omit_groups");
	CONFIG_BOOL_FROM_PLIST(rv, cfg, plist, "omit_apple_hashes");
	CONFIG_STR_FROM_PLIST(rv, cfg, plist, "ancestors");
	CONFIG_STR_FROM_PLIST(rv, cfg, plist, "events");
	CONFIG_STR_FROM_PLIST(rv, cfg, plist, "stats_interval");
	CONFIG_STR_FROM_PLIST(rv, cfg, plist, "rlimit_nofile");
	CONFIG_BOOL_FROM_PLIST(rv, cfg, plist, "debug");
	CONFIG_BOOL_FROM_PLIST(rv, cfg, plist, "suppress_image_exec_at_start");

	/* The strset initializations must be called even if we were to allow
	 * xnumon to run without a config file; they handle plist==NULL. */
	CONFIG_STRSET_FROM_PLIST(rv, cfg, plist,
	                         suppress_image_exec_by_ident);
	CONFIG_STRSET_FROM_PLIST(rv, cfg, plist,
	                         suppress_image_exec_by_path);
	CONFIG_STRSET_FROM_PLIST(rv, cfg, plist,
	                         suppress_image_exec_by_ancestor_ident);
	CONFIG_STRSET_FROM_PLIST(rv, cfg, plist,
	                         suppress_image_exec_by_ancestor_path);
	CONFIG_STRSET_FROM_PLIST(rv, cfg, plist,
	                         suppress_process_access_by_subject_ident);
	CONFIG_STRSET_FROM_PLIST(rv, cfg, plist,
	                         suppress_process_access_by_subject_path);

	if (plist)
		CFRelease(plist);
	return cfg;

errout:
	if (plist)
		CFRelease(plist);
	config_free(cfg);
	return NULL;
}

void
config_free(config_t *cfg) {
	assert(cfg);

	strset_destroy(&cfg->suppress_image_exec_by_ident);
	strset_destroy(&cfg->suppress_image_exec_by_path);
	strset_destroy(&cfg->suppress_image_exec_by_ancestor_ident);
	strset_destroy(&cfg->suppress_image_exec_by_ancestor_path);
	strset_destroy(&cfg->suppress_process_access_by_subject_ident);
	strset_destroy(&cfg->suppress_process_access_by_subject_path);
	if (cfg->path)
		free(cfg->path);
	if (cfg->id)
		free(cfg->id);
	if (cfg->logfile)
		free(cfg->logfile);
	free(cfg);
}

int
config_kextlevel(config_t *cfg, const char *opt) {
	assert(opt);

	if (opt[0] == 'n' || opt[0] == '0') {
		cfg->kextlevel = KEXTLEVEL_NONE;
		return 0;
	}
	if (opt[0] == 'o' || opt[0] == '1') {
		cfg->kextlevel = KEXTLEVEL_OPEN;
		return 0;
	}
	if (opt[0] == 'h' || opt[0] == '2') {
		cfg->kextlevel = KEXTLEVEL_HASH;
		return 0;
	}
	if (opt[0] == 'c' || opt[0] == '3') {
		cfg->kextlevel = KEXTLEVEL_CSIG;
		return 0;
	}
	return -1;
}

static const char *kextlevels[] = {"none", "open", "hash", "csig"};

const char *
config_kextlevel_s(config_t *cfg) {
	return kextlevels[cfg->kextlevel];
}

