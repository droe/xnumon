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
 * File monitoring core.
 */

#include "filemon.h"

#include "work.h"
#include "str.h"
#include "cf.h"
#include "cacheldpl.h"
#include "atomic.h"

#include <stdlib.h>
#include <stdbool.h>
#include <strings.h>
#include <fcntl.h>
#include <glob.h>
#include <paths.h>
#include <assert.h>

static config_t *config;

static uint64_t events_received;    /* number of filesystem events received */
static uint64_t events_processed;   /* number of filesystem events processed */
static atomic64_t ooms;             /* counts events impaired due to OOM */
static atomic64_t lpmisseds;        /* plists that were not present anymore */

static bool
filemon_is_launchd_path(const char *path) {
	const char *p;

	assert(path);
	if (path[0] != '/')
		return false;
	if (str_beginswith(path, "/System/Library/LaunchDaemons/"))
		return true;
	if (str_beginswith(path, "/Library/LaunchDaemons/"))
		return true;
	if (str_beginswith(path, "/System/Library/LaunchAgents/"))
		return true;
	if (str_beginswith(path, "/Library/LaunchAgents/"))
		return true;
	if (!str_beginswith(path, "/Users/"))
		return false;
	p = path + 7;
	while (*p != '/') {
		if (!*p)
			return false;
		p++;
	}
	if (!str_beginswith(p, "/Library/LaunchAgents/"))
		return false;
	return true;
}

static void launchd_add_free(launchd_add_t *);
static int launchd_add_work(launchd_add_t *);

/*
 * Always frees path regardless of success.
 */
static launchd_add_t *
launchd_add_new(char *path) {
	launchd_add_t *ldadd;

	ldadd = malloc(sizeof(*ldadd));
	if (!ldadd) {
		free(path);
		return NULL;
	}
	bzero(ldadd, sizeof(*ldadd));
	ldadd->plist_path = path;
	ldadd->hdr.type = LOGEVT_LAUNCHD_ADD;
	ldadd->hdr.le_work = (__typeof__(ldadd->hdr.le_work))launchd_add_work;
	ldadd->hdr.le_free = (__typeof__(ldadd->hdr.le_free))launchd_add_free;
	return ldadd;
}

static void
launchd_add_free(launchd_add_t *ldadd) {
	if (ldadd->program_path)
		free(ldadd->program_path);
	if (ldadd->program_argv)
		free(ldadd->program_argv);
	if (ldadd->subject_image_exec)
		image_exec_free(ldadd->subject_image_exec);
	free(ldadd->plist_path);
	free(ldadd);
}

static int
launchd_add_open(launchd_add_t *ldadd) {
	ldadd->plist_fd = open(ldadd->plist_path, O_RDONLY);
	if (ldadd->plist_fd == -1)
		return -1;
	return sys_fdattr(&ldadd->plist_stat, ldadd->plist_fd);
}

static void
launchd_add_analyze(launchd_add_t *ldadd) {
	CFPropertyListRef plist;

	assert(ldadd->plist_path);
	plist = cf_plist_load(ldadd->plist_path);
	if (!plist) {
		atomic64_inc(&lpmisseds);
		return;
	}
	ldadd->program_path = cf_cstr(CFDictionaryGetValue(
	                      (CFDictionaryRef)plist,
	                      CFSTR("Program")));
	ldadd->program_argv = cf_aev(CFDictionaryGetValue(
	                      (CFDictionaryRef)plist,
	                      CFSTR("ProgramArguments")));
	CFRelease(plist);
	if (errno == ENOMEM) {
		atomic64_inc(&ooms);
		return;
	}

	if (!ldadd->program_path &&
	    ldadd->program_argv &&
	    ldadd->program_argv[0]) {
		if (ldadd->program_argv[0][0] == '/') {
			/* absolute path */
			ldadd->program_path = strdup(ldadd->program_argv[0]);
		} else if (!!strchr(ldadd->program_argv[0], '/')) {
			/* relative path */
			ldadd->program_path =
				sys_realpath(ldadd->program_argv[0], "/");
		} else {
			/* filename to be searched in PATH */
			ldadd->program_path = sys_which(ldadd->program_argv[0],
			                                _PATH_STDPATH);
		}
	}
	if (!ldadd->program_path) {
		atomic64_inc(&lpmisseds);
		return;
	}

	/*
	 * For now, we are deliberatly not obtaining hashes and codesign status
	 * for the binary that ldadd->program_path points to.  There should be
	 * an eventid==3 event shortly after the eventid==4 event which will
	 * deliver exactly that information.
	 */
}

static void
launchd_add_close(launchd_add_t *ldadd) {
	if (ldadd->plist_fd != -1)
		close(ldadd->plist_fd);
}

static int
launchd_add_work(launchd_add_t *ldadd) {
	launchd_add_analyze(ldadd);
	launchd_add_close(ldadd);
	if (!ldadd->program_path)
		return -1; /* don't log */
	return 0;
}

static void
filemon_launchd_touched(struct timespec *tv, audit_proc_t *subject,
                        char *path) {
	launchd_add_t *ldadd;
	bool hit;

	ldadd = launchd_add_new(path);
	if (!ldadd) {
		atomic64_inc(&ooms);
		return;
	}
	if (launchd_add_open(ldadd) == -1) {
		launchd_add_free(ldadd);
		return;
	}
	hit = cacheldpl_get(ldadd->plist_stat.dev,
	                    ldadd->plist_stat.ino,
	                    ldadd->plist_stat.mtime.tv_sec,
	                    ldadd->plist_stat.ctime.tv_sec,
	                    ldadd->plist_stat.btime.tv_sec);
	if (hit) {
		launchd_add_close(ldadd);
		launchd_add_free(ldadd);
		return;
	}
	cacheldpl_put(ldadd->plist_stat.dev,
	              ldadd->plist_stat.ino,
	              ldadd->plist_stat.mtime.tv_sec,
	              ldadd->plist_stat.ctime.tv_sec,
	              ldadd->plist_stat.btime.tv_sec);
	ldadd->subject_image_exec = image_exec_by_pid(subject->pid);
	ldadd->subject = *subject;
	ldadd->hdr.tv = *tv;
	work_submit(ldadd);
}

/*
 * Called for all file close and rename events with path to the potentially
 * changed file and the pid that triggered the syscall.
 * Guarantees path to be freed regardless of outcome.
 */
void
filemon_touched(struct timespec *tv, audit_proc_t *subject, char *path) {
	events_received++;
	if (filemon_is_launchd_path(path)) {
		events_processed++;
		filemon_launchd_touched(tv, subject, path);
		return;
	}
	free(path);
}

/*
 * Add a single plist file to the launchd plist file cache.
 */
static int
filemon_init_add_plist(const char *path, UNUSED void *udata) {
	stat_attr_t st;
	int rv;

	rv = sys_pathattr(&st, path);
	if (rv != -1) {
		cacheldpl_put(st.dev,
		              st.ino,
		              st.mtime.tv_sec,
		              st.ctime.tv_sec,
		              st.btime.tv_sec);
	}
	return 0;
}

/*
 * Initialize the file monitor and add all the existing plist files to the
 * plist file cache.  We accept that there is a race condition here in that
 * plists added while xnumon is initializing may be missed and end up not added
 * to the cache.  When that happens, a later read on the plist will be handled
 * as if it were a write, essentially just delaying detection.
 */
int
filemon_init(config_t *cfg) {
	config = cfg;
	ooms = 0;
	lpmisseds = 0;
	events_received = 0;
	events_processed = 0;
	glob_t g;

	(void)sys_dir_eachfile("/System/Library/LaunchDaemons/",
	                       filemon_init_add_plist, NULL);
	(void)sys_dir_eachfile("/Library/LaunchDaemons/",
	                       filemon_init_add_plist, NULL);
	(void)sys_dir_eachfile("/System/Library/LaunchAgents/",
	                       filemon_init_add_plist, NULL);
	(void)sys_dir_eachfile("/Library/LaunchAgents/",
	                       filemon_init_add_plist, NULL);

	bzero(&g, sizeof(g));
	glob("/Users/*/Library/LaunchAgents/", 0, NULL, &g);
	for (int i = 0; i < g.gl_matchc; i++) {
		(void)sys_dir_eachfile(g.gl_pathv[i],
		                       filemon_init_add_plist, NULL);
	}
	return 0;
}

void
filemon_fini(void) {
	if (!config)
		return;
	config = NULL;
}

void
filemon_stats(filemon_stat_t *st) {
	assert(st);

	st->receiveds = events_received;
	st->processeds = events_processed;
	st->lpmisseds = (uint64_t)lpmisseds;
	st->ooms = (uint64_t)ooms;
}

