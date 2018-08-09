/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef PROCMON_H
#define PROCMON_H

#include "ipaddr.h"
#include "auevent.h"
#include "config.h"
#include "sys.h"
#include "codesign.h"
#include "strset.h"
#include "log.h"
#include "logevt.h"
#include "debug.h"
#include "attrib.h"

#include <unistd.h>
#include <sys/types.h>
#include <stdbool.h>

typedef struct {
	uint32_t procs;
	uint32_t images;
	uint64_t liveacq;
	uint64_t miss_bypid;
	uint64_t miss_forksubj;
	uint64_t miss_execsubj;
	uint64_t miss_execinterp;
	uint64_t miss_chdirsubj;
	uint64_t miss_getcwd;
	uint64_t ooms;
	uint64_t pqsize;
	uint64_t pqlookup;
	uint64_t pqmiss;
	uint64_t pqdrop;
	uint64_t pqskip;
} procmon_stat_t;

void procmon_fork(struct timespec *, audit_proc_t *, pid_t) NONNULL(1,2);
void procmon_spawn(struct timespec *, audit_proc_t *, pid_t,
                   char *, audit_attr_t *, char **, char **) NONNULL(1,2);
void procmon_exec(struct timespec *, audit_proc_t *,
                  char *, audit_attr_t *, char **, char **) NONNULL(1,2,3);
void procmon_exit(struct timespec *, pid_t) NONNULL(1);
void procmon_wait4(struct timespec *, pid_t) NONNULL(1);
void procmon_chdir(struct timespec *tv, pid_t, char *) NONNULL(1,3);

void procmon_kern_preexec(struct timespec *, pid_t, const char *) NONNULL(1,3);

void procmon_preloadpid(pid_t);

int procmon_init(config_t *) WUNRES NONNULL(1);
void procmon_fini(void);
void procmon_stats(procmon_stat_t *) NONNULL(1);
uint32_t procmon_images(void) WUNRES;
const char * procmon_getcwd(pid_t, struct timespec *tv) WUNRES;

void procmon_socket_create(pid_t, int, int);
void procmon_socket_bind(int *, pid_t, int, ipaddr_t *, uint16_t)
     NONNULL(1,4);
void procmon_socket_state(int *, ipaddr_t **, uint16_t *, pid_t, int)
     NONNULL(1,2);
void procmon_file_open(audit_proc_t *, int, char *) NONNULL(1,3);
void procmon_fd_close(pid_t, int);

/*
 * image_exec_t is both the data structure containing a snapshot of an
 * executable image (processes keep track of their exec image), and is reused
 * as an exec log event in order to avoid allocating and copying all this
 * data doubly.  This reuse accounts for at least some of the complexity in
 * its implementation.
 */
typedef struct image_exec {
	logevt_header_t hdr;

	unsigned long flags;
#define EIFLAG_PIDLOOKUP    0x0001UL  /* image created from pid lookup */
#define EIFLAG_NOPATH       0x0002UL  /* external fetching failed, no path */
#define EIFLAG_STAT         0x0004UL  /* set if stat is fully set */
#define EIFLAG_ATTR         0x0008UL  /* set if stat was populated from attr */
#define EIFLAG_HASHES       0x0010UL  /* set if hashes are available */
#define EIFLAG_SHEBANG      0x0020UL  /* set if file contains #! (is script) */
#define EIFLAG_DONE         0x0040UL  /* set if processing is complete */
#define EIFLAG_ENOMEM       0x0080UL  /* set if parts missing due to ENOMEM */
#define EIFLAG_NOLOG        0x0100UL  /* do not submit this for logging */
#define EIFLAG_NOLOG_KIDS   0x0200UL  /* do not submit children to logging */

	/* open/analysis/close state */
	int fd;

	/* exec data */
	pid_t pid;
	struct timespec fork_tv;
	char **argv; /* free */
	char **envv; /* free */
	char *path; /* free */
	char *cwd; /* free */
	audit_proc_t subject;

	/* stat attrs if EIFLAG_STAT or EIFLAG_ATTR is set */
	stat_attr_t stat;

	/* hashes if EIFLAG_HASHES is set */
	hashes_t hashes;

	/* codesign results, or NULL */
	codesign_t *codesign;

	/* for interpreters, ptr to script file */
	struct image_exec *script;
	/* origin image */
	struct image_exec *prev;

	/* kext prep queue ttl */
	size_t pqttl;
#define MAXPQTTL 16     /* maximum out-of-order window and water level up to
                           which the kextctl file descriptor will be drained
                           with priority versus the auditpipe descriptor */

	size_t refs;
	pthread_mutex_t refsmutex;
} image_exec_t;

image_exec_t * image_exec_by_pid(pid_t, struct timespec *tv) MALLOC NONNULL(2);
void image_exec_free(image_exec_t *) NONNULL(1);
bool image_exec_match_suppressions(image_exec_t *, strset_t *, strset_t *)
     NONNULL(1,2,3) WUNRES;

#endif
