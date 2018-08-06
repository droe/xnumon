/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef AUEVENT_H
#define AUEVENT_H

#include "ipaddr.h"
#include "attrib.h"

#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>
#include <time.h>
#include <stdio.h>

#include <bsm/audit_kevents.h> /* auevent_* take lists of event types */

typedef struct {
	pid_t           pid;
	uid_t           auid;
	uint32_t        sid;
	uid_t           euid;
	gid_t           egid;
	uid_t           ruid;
	gid_t           rgid;
	dev_t           dev;                    /* set if != (dev_t)-1 */
	ipaddr_t        addr;                   /* set if !ipaddr_is_empty() */
} audit_proc_t;

typedef struct {
	mode_t          mode;
	uid_t           uid;
	gid_t           gid;
	dev_t           dev;
	ino_t           ino;
#if 0
	dev_t           rdev;
#endif
} audit_attr_t;

typedef struct {
	bool            present;
	uint64_t        value;
#ifdef DEBUG_AUDITPIPE
	char *          text;                   /* strdup/free */
#endif
} audit_arg_t;

typedef struct {
	u_char *        recbuf;                 /* free */
	int             flags;
#define AEFLAG_ENOMEM 1                         /* ENOMEM encountered */

	uint16_t        type;
	uint16_t        mod;
	struct timespec tv;

	size_t          args_count;
	audit_arg_t     args[UCHAR_MAX+1];

	bool            return_present;
	unsigned char   return_error;
	uint32_t        return_value;

	bool            subject_present;
	audit_proc_t    subject;

	bool            process_present;
	audit_proc_t    process;

	const char *    text;

	/* space for two path arguments (unresolved and resolved) */
	const char *    path[4];
	size_t          attr_count;
	audit_attr_t    attr[2];

	bool            exit_present;
	uint32_t        exit_status;
	uint32_t        exit_return;

	char **         execarg;                /* malloc/free */
	char **         execenv;                /* malloc/free */

#define sockinet_present sockinet_addr.family
	ipaddr_t        sockinet_addr;
	uint16_t        sockinet_port;

	unsigned char   unk_tokids[UCHAR_MAX+1]; /* zero-terminated list */
} audit_event_t;

void auevent_create(audit_event_t *) NONNULL(1);
ssize_t auevent_fread(audit_event_t *ev, const uint16_t[], int, FILE *)
        NONNULL(1,4);
#define AUEVENT_FLAG_ENV_DYLD 1
#define AUEVENT_FLAG_ENV_FULL 2
void auevent_destroy(audit_event_t *) NONNULL(1);
void auevent_fprint(FILE *, audit_event_t *) NONNULL(1,2);

int auevent_init(void) WUNRES;

int auevent_sock_domain(int) WUNRES;
int auevent_sock_type(int) WUNRES;

#endif

