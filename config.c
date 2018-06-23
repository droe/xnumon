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

static int
config_set_bool(bool *b, const char *value) {
	if (!strcmp(value, "true")
	 || !strcmp(value, "yes")
	 || !strcmp(value, "1")) {
		*b = true;
		return 0;
	}
	if (!strcmp(value, "false")
	 || !strcmp(value, "no")
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

	if (!strcmp(key, "ancestors")) {
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

	return -1;
}

static int
config_str_from_plist(config_t *cfg, const char *optname,
                      CFPropertyListRef plist, CFStringRef key) {
	CFStringRef cfs = CFDictionaryGetValue((CFDictionaryRef)plist, key);
	if (cfs) {
		int rv;
		char *s = cf_cstr(cfs);
		if (!s)
			return -1;
		rv = config_str(cfg, optname, s);
		free(s);
		if (rv == -1)
			return -1;
	}
	return 0;
}

static int
config_bool_from_plist(config_t *cfg, const char *optname,
                       CFPropertyListRef plist, CFStringRef key) {
	CFBooleanRef cfb = CFDictionaryGetValue((CFDictionaryRef)plist, key);
	if (cfb) {
		int rv;
		if (CFBooleanGetValue(cfb))
			rv = config_str(cfg, optname, "true");
		else
			rv = config_str(cfg, optname, "false");
		if (rv == -1)
			return -1;
	}
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
	if (!arr)
		return strset_init(set, 0, NULL);
	arrsz = CFArrayGetCount(arr);
	if (arrsz == 0)
		return strset_init(set, 0, NULL);
	v = cf_cstrv(arr);
	if (!v)
		return -1;
	return strset_init(set, arrsz, v);
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
	cfg->stats_interval = 3600;
	cfg->kextlevel = KEXTLEVEL_HASH;
	cfg->hflags = HASH_SHA256;
	cfg->codesign = true;
	cfg->logoneline = -1; /* any */
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
	rv = config_str_from_plist(cfg, "config_id",
	                           plist, CFSTR("config_id"));
	if (rv == -1) {
		fprintf(stderr, "Failed to load 'config_id'\n");
		goto errout;
	}
	rv = config_str_from_plist(cfg, "log_format",
	                           plist, CFSTR("log_format"));
	if (rv == -1) {
		fprintf(stderr, "Failed to load 'log_format'\n");
		goto errout;
	}
	rv = config_str_from_plist(cfg, "log_destination",
	                           plist, CFSTR("log_destination"));
	if (rv == -1) {
		fprintf(stderr, "Failed to load 'log_destination'\n");
		goto errout;
	}
	rv = config_str_from_plist(cfg, "log_mode",
	                           plist, CFSTR("log_mode"));
	if (rv == -1) {
		fprintf(stderr, "Failed to load 'log_mode'\n");
		goto errout;
	}
	rv = config_str_from_plist(cfg, "kextlevel",
	                           plist, CFSTR("kextlevel"));
	if (rv == -1) {
		fprintf(stderr, "Failed to load 'kextlevel'\n");
		goto errout;
	}
	rv = config_str_from_plist(cfg, "hashes",
	                           plist, CFSTR("hashes"));
	if (rv == -1) {
		fprintf(stderr, "Failed to load 'hashes'\n");
		goto errout;
	}
	rv = config_bool_from_plist(cfg, "codesign",
	                            plist, CFSTR("codesign"));
	if (rv == -1) {
		fprintf(stderr, "Failed to load 'codesign'\n");
		goto errout;
	}
	rv = config_str_from_plist(cfg, "ancestors",
	                           plist, CFSTR("ancestors"));
	if (rv == -1) {
		fprintf(stderr, "Failed to load 'ancestors'\n");
		goto errout;
	}
	rv = config_str_from_plist(cfg, "stats_interval",
	                           plist, CFSTR("stats_interval"));
	if (rv == -1) {
		fprintf(stderr, "Failed to load 'stats_interval'\n");
		goto errout;
	}
	rv = config_str_from_plist(cfg, "rlimit_nofile",
	                           plist, CFSTR("rlimit_nofile"));
	if (rv == -1) {
		fprintf(stderr, "Failed to load 'rlimit_nofile'\n");
		goto errout;
	}

	/* The strset initializations must be called even if we were to allow
	 * xnumon to run without a config file; they handle plist==NULL. */
	rv = config_strset_from_plist(&cfg->suppress_image_exec_by_ident,
	                              plist,
	                              CFSTR("suppress_image_exec_by_ident"));
	if (rv == -1) {
		fprintf(stderr,
		        "Failed to load 'suppress_image_exec_by_ident'\n");
		goto errout;
	}
	rv = config_strset_from_plist(&cfg->suppress_image_exec_by_path,
	                              plist,
	                              CFSTR("suppress_image_exec_by_path"));
	if (rv == -1) {
		fprintf(stderr,
		        "Failed to load 'suppress_image_exec_by_path'\n");
		goto errout;
	}
	rv = config_strset_from_plist(&cfg->suppress_process_access_by_ident,
	                              plist,
	                              CFSTR("suppress_process_access_by_ident")
	                              );
	if (rv == -1) {
		fprintf(stderr,
		        "Failed to load 'suppress_process_access_by_ident'\n");
		goto errout;
	}
	rv = config_strset_from_plist(&cfg->suppress_process_access_by_path,
	                              plist,
	                              CFSTR("suppress_process_access_by_path"));
	if (rv == -1) {
		fprintf(stderr,
		        "Failed to load 'suppress_process_access_by_path'\n");
		goto errout;
	}

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
	strset_destroy(&cfg->suppress_process_access_by_ident);
	strset_destroy(&cfg->suppress_process_access_by_path);
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

