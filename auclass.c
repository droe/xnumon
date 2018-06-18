/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include "auclass.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <bsm/audit.h>
#include <bsm/audit_kevents.h>

/*
 * The events that are configured to be part of the custom AC_XNUMON class.
 * This list needs to be in line with what is actually handled in evtloop.c.
 */
const uint16_t auclass_xnumon_events[] = {
	/* process tracking */
	AUE_FORK,       /* fork */
	AUE_VFORK,      /* vfork */
	AUE_POSIX_SPAWN,/* posix_spawn, posix_spawnp +/- POSIX_SPAWN_SETEXEC */
	AUE_EXECVE,  /* execl, execle, execlp, execv, execve, execvp, execvP */
	AUE_MAC_EXECVE, /* __mac_execve */
	AUE_EXIT,       /* exit */
	AUE_WAIT4,      /* wait, wait3, wait4, waitpid */
	/*
	 * AUE_FORK1          - syscall not implemented on macOS
	 * AUE_DARWIN_RFORK   - syscall not implemented on macOS
	 * AUE_EXEC           - syscall not implemented on macOS
	 * AUE_FEXECVE        - syscall not implemented on macOS
	 * Mach task_create   - RPC via mach_msg syscall, always fails
	 */

	/* cwd tracking for handling of relative-path interpreters et al */
	AUE_CHDIR,      /* chdir */
	AUE_FCHDIR,     /* fchdir */

	/* tracking of inter-process access for potential manipulation */
	AUE_PTRACE,     /* ptrace */
	AUE_TASKFORPID, /* task_for_pid */
	                /* processor_set_tasks cannot be audited (40755284);
	                 * but seems to be disarmed in 10.14 */

	/* file modification tracking for monitoring launch daemons */
	AUE_CLOSE,      /* close, close_nocancel, guarded_close_np */
	AUE_RENAME,     /* rename */
	AUE_RENAMEAT,   /* renameat, renameatx_np */
	AUE_UTIMES,     /* utimes */
	AUE_FUTIMES,    /* futimes */
	/*
	 * AUE_UTIME          - syscall not implemented on macOS
	 * AUE_FUTIMESAT      - syscall not implemented on macOS
	 * AUE_LUTIMES        - syscall not implemented on macOS
	 * AUE_DARWIN_FUTIMES - syscall not implemented on macOS
	 */

	0
};

/*
 * Add *classmask* to the classmask of all events in NULL-terminated array of
 * event IDs *aues*.  This global kernel configuration affects all consumers of
 * audit(4), including auditd(8).
 */
int
auclass_addmask(unsigned int classmask, const uint16_t aues[]) {
	au_evclass_map_t auem;

	for (int i = 0; aues[i]; i++) {
		bzero(&auem, sizeof(auem));
		auem.ec_number = aues[i];
		if (auditon(A_GETCLASS, &auem, sizeof(auem)) == -1) {
			fprintf(stderr, "auditon(A_GETCLASS,%u): "
			                "%s (%i)\n", aues[i],
			                strerror(errno), errno);
			return -1;
		}
		auem.ec_class |= classmask;
		if (auditon(A_SETCLASS, &auem, sizeof(auem)) == -1) {
			fprintf(stderr, "auditon(A_SETCLASS,%08x,%u): "
			                "%s (%i)\n",
			                auem.ec_class, auem.ec_number,
			                strerror(errno), errno);
			return -1;
		}
	}
	return 0;
}

/*
 * Remove *classmask* from the classmask of all events in NULL-terminated array
 * of event IDs *aues*.  This global kernel configuration affects all consumers
 * of audit(4), including auditd(8).
 */
int
auclass_removemask(unsigned int classmask, const uint16_t aues[]) {
	au_evclass_map_t auem;

	for (int i = 0; aues[i]; i++) {
		bzero(&auem, sizeof(auem));
		auem.ec_number = aues[i];
		if (auditon(A_GETCLASS, &auem, sizeof(auem)) == -1) {
			fprintf(stderr, "auditon(A_GETCLASS,%u): "
			                "%s (%i)\n", aues[i],
			                strerror(errno), errno);
			return -1;
		}
		auem.ec_class &= ~classmask;
		if (auditon(A_SETCLASS, &auem, sizeof(auem)) == -1) {
			fprintf(stderr, "auditon(A_SETCLASS,%08x,%u): "
			                "%s (%i)\n",
			                auem.ec_class, auem.ec_number,
			                strerror(errno), errno);
			return -1;
		}
	}
	return 0;
}

typedef struct {
	const char *name;
	unsigned int flag;
} class_t;

class_t classes[] = {
	/* non-standard */
	{"xm",      AC_XNUMON},
	{"xnumon",  AC_XNUMON},
	/* standard */
	{"fr",      AC_FREAD},
	{"fread",   AC_FREAD},
	{"fw",      AC_FWRITE},
	{"fwrite",  AC_FWRITE},
	{"fa",      AC_FATTRA},
	{"fattra",  AC_FATTRA},
	{"fm",      AC_FATTRM},
	{"fattrm",  AC_FATTRM},
	{"fc",      AC_FCREAT},
	{"fcreat",  AC_FCREAT},
	{"fd",      AC_FDELET},
	{"fdelet",  AC_FDELET},
	{"cl",      AC_FCLOSE},
	{"fclose",  AC_FCLOSE},
	{"pc",      AC_PROC},
	{"proc",    AC_PROC},
	{"nt",      AC_NET},
	{"net",     AC_NET},
	{"ip",      AC_IPC},
	{"ipc",     AC_IPC},
	{"na",      AC_NA},
	{"ad",      AC_ADMIN},
	{"admin",   AC_ADMIN},
	{"lo",      AC_LOGIN},
	{"login",   AC_LOGIN},
	{"aa",      AC_AUTH},
	{"auth",    AC_AUTH},
	{"ap",      AC_APP},
	{"app",     AC_APP},
	{"io",      AC_IOCTL},
	{"ioctl",   AC_IOCTL},
	{"ex",      AC_EXEC},
	{"exec",    AC_EXEC},
	{"ot",      AC_MISC},
	{"misc",    AC_MISC},
	{"all",     AC_ALL},
	{"file",    AC_FILE},
	{0, 0}
};

static unsigned int
auclass_parse(const char *s, size_t l) {
	for (int i = 0; classes[i].name; i++)
		if (!strncmp(s, classes[i].name, l) &&
		    l == strlen(classes[i].name) &&
		    classes[i].name[l] == '\0')
			return classes[i].flag;
	return AC_NONE;
}

unsigned int
auclass_maskparse(const char *s) {
	unsigned int classmask = AC_NONE;
	const char *begin, *end;

	begin = s;
	for (;;) {
		end = begin;
		while ((*end != '\0') && (*end != ','))
			end++;
		classmask |= auclass_parse(begin, end-begin);
		if (!*end)
			break;
		begin = end + 1;
	}

	return classmask;
}

