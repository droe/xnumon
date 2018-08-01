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
 * Monitoring core for network sockets.
 */

#include "sockmon.h"

#include "work.h"
#include "atomic.h"

#include <strings.h>
#include <assert.h>

static config_t *config;

static uint64_t events_recvd;   /* number of events received */
static uint64_t events_procd;   /* number of events processed */
static atomic64_t ooms;         /* counts events impaired due to OOM */

strset_t *suppress_socket_op_by_subject_ident;
strset_t *suppress_socket_op_by_subject_path;

static void socket_op_free(socket_op_t *);
static int socket_op_work(socket_op_t *);

static socket_op_t *
socket_op_new(uint64_t code) {
	socket_op_t *so;

	so = malloc(sizeof(*so));
	if (!so)
		return NULL;
	bzero(so, sizeof(*so));
	so->hdr.code = code;
	so->hdr.le_work = (__typeof__(so->hdr.le_work))socket_op_work;
	so->hdr.le_free = (__typeof__(so->hdr.le_free))socket_op_free;
	return so;
}

static void
socket_op_free(socket_op_t *so) {
	if (so->subject_image_exec)
		image_exec_free(so->subject_image_exec);
	free(so);
}

/*
 * Executed by worker thread.
 *
 * Returns -1 if this work item should not be logged, 0 otherwise.
 */
static int
socket_op_work(socket_op_t *so) {
	if (so->subject_image_exec && image_exec_match_suppressions(
	                              so->subject_image_exec,
	                              suppress_socket_op_by_subject_ident,
	                              suppress_socket_op_by_subject_path))
		return -1;
	return 0;
}

static void
log_event_socket_op(struct timespec *tv,
                    audit_proc_t *subject,
                    ipaddr_t *addr, uint16_t port, bool success,
                    uint64_t code) {
	socket_op_t *so;

	so = socket_op_new(code);
	if (!so) {
		atomic64_inc(&ooms);
		return;
	}
	so->subject_image_exec = image_exec_by_pid(subject->pid);
	so->subject = *subject;
	so->addr = *addr;
	so->port = port;
	so->success = success;
	so->hdr.tv = *tv;
	work_submit(so);
}

static void
sockmon_socket_op(struct timespec *tv,
                  audit_proc_t *subject,
                  ipaddr_t *addr, uint16_t port, bool success,
                  uint64_t code) {
	events_recvd++;
	events_procd++;
	log_event_socket_op(tv, subject, addr, port, success, code);
}

/*
 * Called for bind.
 *
 * XXX should remember binds per socket+process and log listen instead of bind
 */
void
sockmon_bind(struct timespec *tv,
             audit_proc_t *subject,
             ipaddr_t *addr, uint16_t port) {
	sockmon_socket_op(tv, subject, addr, port, true,
	                  LOGEVT_SOCKET_BIND);
}

/*
 * Called for accept.
 */
void
sockmon_accept(struct timespec *tv,
               audit_proc_t *subject,
               ipaddr_t *addr, uint16_t port) {
	sockmon_socket_op(tv, subject, addr, port, true,
	                  LOGEVT_SOCKET_ACCEPT);
}

/*
 * Called for connect.
 */
void
sockmon_connect(struct timespec *tv,
                audit_proc_t *subject,
                ipaddr_t *addr, uint16_t port, bool success) {
	sockmon_socket_op(tv, subject, addr, port, success,
	                  LOGEVT_SOCKET_CONNECT);
}

void
sockmon_init(config_t *cfg) {
	config = cfg;
	ooms = 0;
	events_recvd = 0;
	events_procd = 0;
	suppress_socket_op_by_subject_ident =
		&cfg->suppress_socket_op_by_subject_ident;
	suppress_socket_op_by_subject_path =
		&cfg->suppress_socket_op_by_subject_path;
}

void
sockmon_fini(void) {
	if (!config)
		return;
	config = NULL;
}

void
sockmon_stats(sockmon_stat_t *st) {
	assert(st);

	st->recvd = events_recvd;
	st->procd = events_procd;
	st->ooms = (uint64_t)ooms;
}

