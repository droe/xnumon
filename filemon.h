/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef FILEMON_H
#define FILEMON_H

#include "auevent.h"
#include "procmon.h"
#include "logevt.h"
#include "sys.h"
#include "config.h"
#include "attrib.h"

#include <sys/types.h>

typedef struct {
	uint64_t recvd;
	uint64_t procd;
	uint64_t lpmiss;
	uint64_t ooms;
} filemon_stat_t;

typedef struct {
	logevt_header_t hdr;

	unsigned long flags;
#define LAFLAG_NOSUBJECT 0x00000001

	/* process which touched the plist file */
	audit_proc_t subject;
	image_exec_t *subject_image_exec;
	/* plist file */
	char *plist_path;
	int plist_fd;
	stat_attr_t plist_stat;
	/* daemon or agent program read from the plist file */
	char *program_path;
	char **program_argv;
	char *program_rpath; /* resolved absolute path or argv[0] */
} launchd_add_t;

void filemon_touched(struct timespec *, audit_proc_t *, char *)
     NONNULL(1,2,3);
void filemon_symlink(struct timespec *, audit_proc_t *, char *)
     NONNULL(1,2,3);

int filemon_init(config_t *) WUNRES NONNULL(1);
void filemon_fini(void);
void filemon_stats(filemon_stat_t *) NONNULL(1);

#endif
