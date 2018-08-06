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
                    int protocol,
                    ipaddr_t *sock_addr, uint16_t sock_port,
                    ipaddr_t *peer_addr, uint16_t peer_port,
                    uint64_t eventcode) {
	socket_op_t *so;

	so = socket_op_new(eventcode);
	if (!so) {
		atomic64_inc(&ooms);
		return;
	}
	so->subject_image_exec = image_exec_by_pid(subject->pid);
	so->subject = *subject;
	/* can be 0 if unknown */
	so->protocol = protocol;
	/* can be 0 if unknown or irrelevant */
	if (sock_addr) {
		so->sock_addr = *sock_addr;
		so->sock_port = sock_port;
	}
	/* can be 0 if unknown or irrelevant */
	if (peer_addr) {
		so->peer_addr = *peer_addr;
		so->peer_port = peer_port;
	}
	so->hdr.tv = *tv;
	work_submit(so);
}

static void
sockmon_socket_op(struct timespec *tv,
                  audit_proc_t *subject,
                  int protocol /* can be 0 */,
                  ipaddr_t *sock_addr /* can be NULL */ , uint16_t sock_port,
                  ipaddr_t *peer_addr /* can be NULL */, uint16_t peer_port,
                  uint64_t eventcode) {
	events_recvd++;
	if (config->suppress_socket_op_localhost) {
		if (peer_addr) {
			if (ipaddr_is_localhost(peer_addr))
				return;
		} else if (sock_addr) {
			if (ipaddr_is_localhost(sock_addr))
				return;
		}
	}
	events_procd++;
	log_event_socket_op(tv, subject, protocol, sock_addr, sock_port,
	                    peer_addr, peer_port, eventcode);
}

/*
 * Called for socket.
 */
void
sockmon_socket(UNUSED struct timespec *tv,
               audit_proc_t *subject,
               int fd, int domain, int type, int protocol) {
	events_recvd++;
	if (domain != PF_INET && domain != PF_INET6/*XXX && domain != PF_NDRW*/)
		return;
	if (protocol == 0) {
		if (type == SOCK_STREAM)
			protocol = IPPROTO_TCP;
		else if (type == SOCK_DGRAM)
			protocol = IPPROTO_UDP;
		else
			return;
	}
	events_procd++;
	procmon_socket_create(subject->pid, fd, protocol);
}

/*
 * Called for bind.
 */
void
sockmon_bind(UNUSED struct timespec *tv,
             audit_proc_t *subject,
             int fd, ipaddr_t *sock_addr, uint16_t sock_port) {
	int proto;

	events_recvd++;
	events_procd++;
	procmon_socket_bind(&proto, subject->pid, fd, sock_addr, sock_port);
	if (proto == IPPROTO_UDP) {
		/* trigger listen event, there will not be a listen() */
		sockmon_socket_op(tv, subject, proto, sock_addr, sock_port,
		                  NULL, 0, LOGEVT_SOCKET_LISTEN);
	}
}

/*
 * Called for listen.
 */
void
sockmon_listen(struct timespec *tv,
               audit_proc_t *subject,
               int fd) {
	int proto;
	ipaddr_t *addr;
	uint16_t port;

	procmon_socket_state(&proto, &addr, &port, subject->pid, fd);
	sockmon_socket_op(tv, subject, proto, addr, port, NULL, 0,
	                  LOGEVT_SOCKET_LISTEN);
}

/*
 * Called for accept.
 */
void
sockmon_accept(struct timespec *tv,
               audit_proc_t *subject,
               int fd, ipaddr_t *peer_addr, uint16_t peer_port) {
	int proto;
	ipaddr_t *addr;
	uint16_t port;

	procmon_socket_state(&proto, &addr, &port, subject->pid, fd);
	sockmon_socket_op(tv, subject, proto, addr, port, peer_addr, peer_port,
	                  LOGEVT_SOCKET_ACCEPT);
}

/*
 * Called for connect.
 */
void
sockmon_connect(struct timespec *tv,
                audit_proc_t *subject,
                int fd, ipaddr_t *peer_addr, uint16_t peer_port) {
	int proto;
	ipaddr_t *addr;
	uint16_t port;

	procmon_socket_state(&proto, &addr, &port, subject->pid, fd);
	sockmon_socket_op(tv, subject, proto, addr, port, peer_addr, peer_port,
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

