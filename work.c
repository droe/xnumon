/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include "work.h"

#include "logevt.h"
#include "queue.h"
#include "log.h"
#include "policy.h"

#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>

static queue_t work_queue;
static pthread_t work_thr;
static logevt_header_t work_sentinel;

static config_t *config = NULL;

void
work_submit(void *data) {
	logevt_header_t *hdr = data;

	assert(hdr);
	assert(hdr->le_free);
	queue_enqueue(&work_queue, &hdr->node, hdr);
}

static void *
work_thread(UNUSED void *arg) {
	logevt_header_t *hdr;

#if 0	/* terra pericolosa */
	(void)policy_thread_sched_standard();
#endif
	(void)policy_thread_diskio_standard();

	for (;;) {
		hdr = queue_dequeue(&work_queue);
		if (hdr == &work_sentinel)
			break;
		if (hdr->le_work) {
			if (hdr->le_work(hdr) == -1) {
				hdr->le_free(hdr);
				continue;
			}
		}
		if (!LOGEVT_WANT(config->events, LOGEVT_FLAG(hdr->code))) {
			hdr->le_free(hdr);
			continue;
		}
		log_submit(hdr);
	}
	return NULL;
}

int
work_init(config_t *cfg) {
	queue_init(&work_queue);
	if (pthread_create(&work_thr, NULL, work_thread, NULL) != 0) {
		queue_destroy(&work_queue);
		return -1;
	}
	config = cfg;
	return 0;
}

void
work_fini(void) {
	if (!config)
		return;

	bzero(&work_sentinel, sizeof(work_sentinel));
	queue_enqueue(&work_queue, &work_sentinel.node, &work_sentinel);
	if (pthread_join(work_thr, NULL) != 0) {
		fprintf(stderr, "Failed to join worker thread - exiting\n");
		exit(EXIT_FAILURE);
	}
	assert(queue_size(&work_queue) == 0);
	queue_destroy(&work_queue);
	config = NULL;
}

void
work_stats(work_stat_t *st) {
	assert(st);

	st->qsize = queue_size(&work_queue);
}

