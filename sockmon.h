/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef SOCKMON_H
#define SOCKMON_H

#include "auevent.h"
#include "procmon.h"
#include "logevt.h"
#include "sys.h"
#include "config.h"
#include "attrib.h"

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct {
	uint64_t recvd;
	uint64_t procd;
	uint64_t ooms;
} sockmon_stat_t;

typedef struct {
	logevt_header_t hdr;
	audit_proc_t subject;
	image_exec_t *subject_image_exec;
	ipaddr_t addr;
	uint16_t port;
	bool success;
} socket_op_t;
#define socket_bind_t       socket_op_t
#define socket_accept_t     socket_op_t
#define socket_connect_t    socket_op_t

void sockmon_bind(struct timespec *, audit_proc_t *, ipaddr_t *, uint16_t)
     NONNULL(1,2,3);
void sockmon_accept(struct timespec *, audit_proc_t *, ipaddr_t *, uint16_t)
     NONNULL(1,2,3);
void sockmon_connect(struct timespec *, audit_proc_t *, ipaddr_t *, uint16_t,
                     bool success)
     NONNULL(1,2,3);

void sockmon_init(config_t *) NONNULL(1);
void sockmon_fini(void);
void sockmon_stats(sockmon_stat_t *) NONNULL(1);

#endif

