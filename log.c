/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include "log.h"
#include "logfmt.h"
#include "logfmtjson.h"
#include "logfmtyaml.h"
#include "logdstfile.h"
#include "logdststdout.h"
#include "logdstsyslog.h"

#include "queue.h"
#include "attrib.h"
#include "policy.h"
#include "time.h"
#include "work.h"
#include "evtloop.h"

#include <string.h>
#include <assert.h>

/*
 * Log events.
 */
typedef int (*logevt_func_t)(logfmt_t *, FILE *, void *) NONNULL(1,2) WUNRES;
logevt_func_t le_logevt[LOGEVT_SIZE] = {
	logevt_xnumon_ops,
	logevt_xnumon_stats,
	logevt_image_exec,
	logevt_process_access,
	logevt_launchd_add,
};
_Static_assert(LOGEVT_SIZE == 5, "number of logevt types initialized above");


/*
 * Log formats.
 */
#define LOGFMTS 2
static logfmt_t *logfmttab[LOGFMTS] = {
	&logfmtjson,
	&logfmtyaml
};


/*
 * Log destinations.
 *
 * We may want to refactor this along the lines of logfmt above.
 */
typedef int (*logdst_init_func_t)(config_t *);
typedef int (*logdst_reinit_func_t)(void);
typedef void (*logdst_fini_func_t)(void);
typedef FILE * (*logdst_open_func_t)(void);
typedef int (*logdst_close_func_t)(FILE *);
typedef struct {
	const char *ld_name;
	int ld_oneline;
	int ld_multiline;
	int ld_onelineprefered;
	logdst_init_func_t ld_init;
	logdst_reinit_func_t ld_reinit;
	logdst_fini_func_t ld_fini;
	logdst_open_func_t ld_open;
	logdst_close_func_t ld_close;
} logdst_t;

#define LOGDSTS 3
static logdst_t logdsttab[LOGDSTS] = {
	{
		"file", 1, 1, 1,
		logdstfile_init,
		logdstfile_reinit,
		logdstfile_fini,
		logdstfile_open,
		logdstfile_close
	},
	{
		"-", 1, 1, 0,
		logdststdout_init,
		NULL,
		logdststdout_fini,
		logdststdout_open,
		logdststdout_close
	},
	{
		"syslog", 1, 0, 1,
		logdstsyslog_init,
		NULL,
		logdstsyslog_fini,
		logdstsyslog_open,
		logdstsyslog_close
	}
};

int
logdst_parse(config_t *cfg, const char *name) {
	assert(cfg);
	assert(name);
	for (size_t i = 1; i < LOGDSTS; i++) {
		if (!strcmp(logdsttab[i].ld_name, name)) {
			cfg->logdst = i;
			return 0;
		}
	}
	if (cfg->logfile)
		free(cfg->logfile);
	cfg->logfile = strdup(name);
	if (!cfg->logfile)
		return -1;
	cfg->logdst = 0;
	return 0;
}

const char *
logdst_s(config_t *cfg) {
	return logdsttab[cfg->logdst].ld_name;
}

int
logfmt_parse(config_t *cfg, const char *name) {
	assert(cfg);
	assert(name);
	for (size_t i = 0; i < LOGFMTS; i++) {
		if (!strcmp(logfmttab[i]->lf_name, name)) {
			cfg->logfmt = i;
			return 0;
		}
	}
	return -1;
}

const char *
logfmt_s(config_t *cfg) {
	return logfmttab[cfg->logfmt]->lf_name;
}

static int log_initialized = 0;
static int logfmt = -1;
static int logdst = -1;
static queue_t log_queue;
static pthread_t log_thr;
static logevt_header_t log_sentinel;

static uint64_t counts[LOGEVT_SIZE];
static uint64_t errors;

static int
log_log(logevt_header_t *hdr) {
	FILE *f;
	int rv;

	assert(logdst != -1);
	assert(logfmt != -1);
	assert(hdr->code >= 0 && hdr->code < LOGEVT_SIZE);

	f = logdsttab[logdst].ld_open();
	if (!f)
		return -1;
	rv = le_logevt[hdr->code](logfmttab[logfmt], f, hdr);
	if (rv == 0)
		counts[hdr->code]++;
	else
		errors++;
	if (logdsttab[logdst].ld_close(f) == -1)
		errors++;
	assert(hdr->le_free);
	hdr->le_free(hdr);
	return rv;
}

static void *
log_thread(UNUSED void *arg) {
	logevt_header_t *hdr;

#if 0	/* terra pericolosa */
	(void)policy_thread_sched_standard();
#endif
	(void)policy_thread_diskio_utility();

	for (;;) {
		hdr = queue_dequeue(&log_queue);
		if (hdr == &log_sentinel)
			break;
		(void)log_log(hdr);
	}

	return NULL;
}

int
log_init(config_t *cfg) {
	logfmt = cfg->logfmt;
	logdst = cfg->logdst;
	if ((!logfmttab[logfmt]->lf_oneline &&
	     !logdsttab[logdst].ld_multiline) ||
	    (!logfmttab[logfmt]->lf_multiline &&
	     !logdsttab[logdst].ld_oneline)) {
		fprintf(stderr, "Incompatible logfmt and logdst\n");
		return -1;
	}
	if (cfg->logoneline == -1)
		cfg->logoneline = logdsttab[logdst].ld_onelineprefered;
	if (cfg->logoneline && (!logfmttab[logfmt]->lf_oneline ||
	                        !logdsttab[logdst].ld_oneline))
		cfg->logoneline = 0;
	if (!cfg->logoneline && (!logfmttab[logfmt]->lf_multiline ||
	                         !logdsttab[logdst].ld_multiline))
		cfg->logoneline = 1;
	logevt_init(cfg);
	if (logfmttab[logfmt]->lf_init(cfg) == -1) {
		fprintf(stderr, "Failed to initialize logfmt %i\n", logfmt);
		return -1;
	}
	if (logdsttab[logdst].ld_init(cfg) == -1) {
		fprintf(stderr, "Failed to initialize logdst %i\n", logdst);
		return -1;
	}
	queue_init(&log_queue);
	if (pthread_create(&log_thr, NULL, log_thread, NULL) != 0) {
		queue_destroy(&log_queue);
		logdsttab[logdst].ld_fini();
		return -1;
	}
	errors = 0;
	for (int i = 0; i < LOGEVT_SIZE; i++) {
		counts[i] = 0;
	}
	log_initialized = 1;
	return 0;
}

int
log_reinit(void) {
	assert(log_initialized);
	if (!logdsttab[logdst].ld_reinit)
		return 0;
	if (logdsttab[logdst].ld_reinit() == -1) {
		fprintf(stderr, "Failed to reinitialize logdst %i\n", logdst);
		return -1;
	}
	return 0;
}

void
log_fini(void) {
	if (!log_initialized)
		return;

	bzero(&log_sentinel, sizeof(log_sentinel));
	queue_enqueue(&log_queue, &log_sentinel.node, &log_sentinel);
	if (pthread_join(log_thr, NULL) != 0) {
		fprintf(stderr, "Failed to join logger thread - exiting\n");
		exit(EXIT_FAILURE);
	}
	assert(queue_size(&log_queue) == 0);
	queue_destroy(&log_queue);
	logdsttab[logdst].ld_fini();
	logfmt = -1;
	logdst = -1;
	log_initialized = 0;
}

void
log_submit(void *data) {
	logevt_header_t *hdr = data;

	assert(hdr);
	assert(hdr->code >= 0);
	assert(hdr->code <= LOGEVT_SIZE);
	assert(hdr->tv.tv_sec > 0);
	assert(hdr->le_free);
	queue_enqueue(&log_queue, &hdr->node, hdr);
}

void
log_stats(log_stat_t *st) {
	assert(st);

	st->qsize = queue_size(&log_queue);
	st->errors = errors;
	for (size_t i = 0; i < LOGEVT_SIZE; i++)
		st->counts[i] = counts[i];
}

void
log_version(FILE *f) {
	fprintf(f, "Log event version: %i\n", LOGEVT_VERSION);

	fprintf(f, "Available log formats are:");
	for (size_t i = 0; i < LOGFMTS; i++) {
		fprintf(f, " %s", logfmttab[i]->lf_name);
	}
	fprintf(f, "\n");

	fprintf(f, "Available log destinations are:");
	for (size_t i = 0; i < LOGDSTS; i++) {
		fprintf(f, " %s", logdsttab[i].ld_name);
	}
	fprintf(f, "\n");
}

/*
 * Convenience function to generate and submit a xnumon-ops event.
 */
static int
log_event_xnumon_ops(const char *subtype) {
	xnumon_ops_t *evt;

	evt = malloc(sizeof(xnumon_ops_t));
	if (!evt)
		return -1;
	bzero(evt, sizeof(xnumon_ops_t));
	evt->hdr.code = LOGEVT_XNUMON_OPS;
	if (timespec_nanotime(&evt->hdr.tv) == -1) {
		free(evt);
		return -1;
	}
	evt->hdr.le_free = free;
	evt->subtype = subtype;
	work_submit(evt);
	return 0;
}

/*
 * Convenience function to generate and submit a xnumon-ops(start) event.
 */
int
log_event_xnumon_start(void) {
	return log_event_xnumon_ops("start");
}

/*
 * Convenience function to generate and submit a xnumon-ops(stop) event.
 */
int
log_event_xnumon_stop(void) {
	return log_event_xnumon_ops("stop");
}

/*
 * Convenience function to generate and submit a xnumon stats event.
 */
int
log_event_xnumon_stats(void) {
	evtloop_stat_t *st;

	st = malloc(sizeof(evtloop_stat_t));
	if (!st)
		return -1;
	bzero(st, sizeof(evtloop_stat_t));
	evtloop_stats(st);
	st->hdr.code = LOGEVT_XNUMON_STATS;
	if (timespec_nanotime(&st->hdr.tv) == -1) {
		free(st);
		return -1;
	}
	st->hdr.le_free = free;
	work_submit(st);
	return 0;
}

