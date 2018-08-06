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
 * These lists need to be in line with what is actually handled in evtloop.c.
 */

/*
 * Process tracking.
 */
const uint16_t auclass_xnumon_events_procmon[] = {
	AUE_FORK,       /* fork */
	AUE_VFORK,      /* vfork */
	AUE_POSIX_SPAWN,/* posix_spawn, posix_spawnp +/- POSIX_SPAWN_SETEXEC */
	AUE_EXECVE,  /* execl, execle, execlp, execv, execve, execvp, execvP */
	AUE_MAC_EXECVE, /* __mac_execve */
	AUE_EXIT,       /* exit */
	AUE_WAIT4,      /* wait, wait3, wait4, waitpid */
	AUE_CHDIR,      /* chdir */
	AUE_FCHDIR,     /* fchdir */
	/*
	 * AUE_FORK1          - syscall not implemented on macOS
	 * AUE_DARWIN_RFORK   - syscall not implemented on macOS
	 * AUE_EXEC           - syscall not implemented on macOS
	 * AUE_FEXECVE        - syscall not implemented on macOS
	 * Mach task_create   - RPC via mach_msg syscall, always fails
	 */
	0
};

/*
 * Tracking of inter-process access for potential manipulation.
 */
const uint16_t auclass_xnumon_events_hackmon[] = {
	AUE_PTRACE,     /* ptrace */
	AUE_TASKFORPID, /* task_for_pid */
	                /* processor_set_tasks cannot be audited (40755284);
	                 * but seems to be disarmed in 10.14 */
	0
};

/*
 * File modification tracking.
 *
 * The number and hotness of the events we need to track here seems excessive;
 * there should be better ways to achieve the same.
 */
const uint16_t auclass_xnumon_events_filemon[] = {
#if 0
	AUE_OPEN_W,   /* open, open_nocancel, guarded_open_np */
	AUE_OPEN_WC,
	AUE_OPEN_WT,
	AUE_OPEN_WTC,
	AUE_OPEN_RW,
	AUE_OPEN_RWC,
	AUE_OPEN_RWT,
	AUE_OPEN_RWTC,
	AUE_OPEN_EXTENDED_W, /* open_extended */
	AUE_OPEN_EXTENDED_WC,
	AUE_OPEN_EXTENDED_WT,
	AUE_OPEN_EXTENDED_WTC,
	AUE_OPEN_EXTENDED_RW,
	AUE_OPEN_EXTENDED_RWC,
	AUE_OPEN_EXTENDED_RWT,
	AUE_OPEN_EXTENDED_RWTC,
	AUE_OPENAT_W,   /* openat, openat_nocancel */
	AUE_OPENAT_WC,
	AUE_OPENAT_WT,
	AUE_OPENAT_WTC,
	AUE_OPENAT_RW,
	AUE_OPENAT_RWC,
	AUE_OPENAT_RWT,
	AUE_OPENAT_RWTC,
	AUE_OPENBYID_W, /* openbyid_np */
	AUE_OPENBYID_WT,
	AUE_OPENBYID_RW,
	AUE_OPENBYID_RWT,
	AUE_DUP,        /* dup */
	AUE_DUP2,       /* dup2 */
	AUE_MMAP,       /* mmap */
	AUE_MUNMAP,     /* munmap */
#endif
	AUE_CLOSE,      /* close, close_nocancel, guarded_close_np */
	AUE_RENAME,     /* rename */
	AUE_RENAMEAT,   /* renameat, renameatx_np */
	AUE_LINK,       /* link */
	AUE_LINKAT,     /* linkat */
	AUE_SYMLINK,    /* symlink */
	AUE_SYMLINKAT,  /* symlinkat */
	AUE_UTIMES,     /* utimes */
	AUE_FUTIMES,    /* futimes */
	AUE_COPYFILE,   /* copyfile, fcopyfile */
	AUE_CLONEFILEAT, /* clonefileat */
	AUE_FCLONEFILEAT, /* fclonefileat */
	/*
	 * AUE_CREAT          - syscall not implemented on macOS
	 * AUE_UTIME          - syscall not implemented on macOS
	 * AUE_FUTIMESAT      - syscall not implemented on macOS
	 * AUE_LUTIMES        - syscall not implemented on macOS
	 * AUE_DARWIN_FUTIMES - syscall not implemented on macOS
	 */
	0
};

/* Socket tracking, TCP only for now. */
const uint16_t auclass_xnumon_events_sockmon[] = {
	AUE_SOCKET,
	AUE_BIND,
	AUE_LISTEN,
	AUE_CONNECT,
	AUE_ACCEPT,
#if 0
	AUE_RECVMSG,
	AUE_SENDMSG,
	AUE_RECVFROM,
	AUE_SENDTO,
	AUE_SHUTDOWN,
#endif
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

