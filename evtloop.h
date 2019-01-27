/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2019, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef EVTLOOP_H
#define EVTLOOP_H

#include "config.h"
#include "kqueue.h"
#include "aupipe.h"
#include "kextctl.h"
#include "procmon.h"
#include "hackmon.h"
#include "filemon.h"
#include "log.h"
#include "work.h"
#include "cachehash.h"
#include "cachecsig.h"
#include "cacheldpl.h"
#include "logevt.h"
#include "attrib.h"

typedef struct {
	logevt_header_t hdr;

	procmon_stat_t pm;
	filemon_stat_t fm;
	hackmon_stat_t hm;
	xnumon_stat_t ke;
	uint64_t el_aueunknowns;
	uint64_t el_aupclobbers;
	uint64_t el_failedsyscalls;
	uint64_t el_radar38845422_fatal;
	uint64_t el_radar38845422;
	uint64_t el_radar38845784;
	uint64_t el_radar39267328_fatal;
	uint64_t el_radar39267328;
	uint64_t el_radar39623812_fatal;
	uint64_t el_radar39623812;
	uint64_t el_missingtoken;
	uint64_t el_ooms;
	aupipe_stat_t ap;
	work_stat_t wq;
	log_stat_t lq;
	lrucache_stat_t ch;
	lrucache_stat_t cc;
	lrucache_stat_t cl;
} evtloop_stat_t;

int evtloop_run(config_t *) NONNULL(1);
void evtloop_stats(evtloop_stat_t *) NONNULL(1);

#endif

