/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2019, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include "log.h"
#include "logfmt.h"
#include "logfmtjson.h"
#include "logfmtyaml.h"
#include "logfmtxml.h"
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
static logfmt_t *logfmttab[] = {
	&logfmtjson,
	&logfmtjsonseq,
	&logfmtyaml,
	&logfmtxml
};
#define LOGFMTS (sizeof(logfmttab)/sizeof(logfmttab[0]))

/*
 * Log destinations.
 */
static logdst_t *logdsttab[] = {
	&logdstfile,
	&logdststdout,
	&logdstsyslog
};
#define LOGDSTS (sizeof(logdsttab)/sizeof(logdsttab[0]))

int
logdst_parse(config_t *cfg, const char *name) {
	assert(cfg);
	assert(name);
	for (size_t i = 1; i < LOGDSTS; i++) {
		if (!strcmp(logdsttab[i]->ld_name, name)) {
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
	return logdsttab[cfg->logdst]->ld_name;
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

static bool log_initialized = false;
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
	assert(logdsttab[logdst]->ld_raw || logfmt != -1);
	assert(hdr->code >= 0 && hdr->code < LOGEVT_SIZE);

	if (logdsttab[logdst]->ld_raw) {
		rv = logdsttab[logdst]->ld_event(hdr);
	} else {
		f = logdsttab[logdst]->ld_open();
		if (!f)
			return -1;
		rv = le_logevt[hdr->code](logfmttab[logfmt], f, hdr);
		if (logdsttab[logdst]->ld_close(f) == -1)
			errors++;
	}
	if (rv == 0)
		counts[hdr->code]++;
	else
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
	logdst = cfg->logdst;
	if (!logdsttab[logdst]->ld_raw) {
		logfmt = cfg->logfmt;
		if ((!logfmttab[logfmt]->lf_oneline &&
		     !logdsttab[logdst]->ld_multiline) ||
		    (!logfmttab[logfmt]->lf_multiline &&
		     !logdsttab[logdst]->ld_oneline)) {
			fprintf(stderr, "Incompatible logfmt and logdst\n");
			return -1;
		}
		if (cfg->logoneline == -1)
			cfg->logoneline =
				logdsttab[logdst]->ld_onelineprefered ? 1 : 0;
		if (cfg->logoneline && (!logfmttab[logfmt]->lf_oneline ||
		                        !logdsttab[logdst]->ld_oneline))
			cfg->logoneline = 0;
		if (!cfg->logoneline && (!logfmttab[logfmt]->lf_multiline ||
		                         !logdsttab[logdst]->ld_multiline))
			cfg->logoneline = 1;
	}
	logevt_init(cfg);
	if (!logdsttab[logdst]->ld_raw) {
		if (logfmttab[logfmt]->lf_init(cfg) == -1) {
			fprintf(stderr, "Failed to initialize logfmt %i\n",
			                logfmt);
			return -1;
		}
	}
	if (logdsttab[logdst]->ld_init(cfg) == -1) {
		fprintf(stderr, "Failed to initialize logdst %i\n", logdst);
		return -1;
	}
	queue_init(&log_queue);
	if (pthread_create(&log_thr, NULL, log_thread, NULL) != 0) {
		queue_destroy(&log_queue);
		logdsttab[logdst]->ld_fini();
		return -1;
	}
	errors = 0;
	for (int i = 0; i < LOGEVT_SIZE; i++) {
		counts[i] = 0;
	}
	log_initialized = true;
	return 0;
}

int
log_reinit(void) {
	assert(log_initialized);
	if (!logdsttab[logdst]->ld_reinit)
		return 0;
	if (logdsttab[logdst]->ld_reinit() == -1) {
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
	logdsttab[logdst]->ld_fini();
	logfmt = -1;
	logdst = -1;
	log_initialized = false;
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
		fprintf(f, " %s", logdsttab[i]->ld_name);
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

