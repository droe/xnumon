/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include "auevent.h"

#include "aupipe.h"
#include "minmax.h"
#include "sys.h"
#include "aev.h"

#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <limits.h>

#include <bsm/libbsm.h>
#include <bsm/audit_kevents.h>

/*
 * Record token structs in libbsm:
 * https://github.com/openbsm/openbsm/blob/master/bsm/libbsm.h
 *
 * AUT_* token constants in kernel:
 * https://github.com/apple/darwin-xnu/blob/master/bsd/bsm/audit_record.h
 *
 * AUE_* event constants in kernel:
 * https://github.com/apple/darwin-xnu/blob/master/bsd/bsm/audit_kevents.h
 */

static dev_t devnull;

int
auevent_init(void) {
	devnull = sys_devbypath("/dev/null");
	if (devnull == (dev_t)-1)
		return -1;
	return 0;
}

#define SET_DEV(DST_DEV, SRC_TID) \
	DST_DEV = ((dev_t)(SRC_TID).port) == devnull ? -1 : (SRC_TID).port;

#define SET_ADDR(DST_ADDR, SRC_TID) \
	if ((SRC_TID).addr != 0) { \
		(DST_ADDR).family = AF_INET; \
		(DST_ADDR).ev_addr = (SRC_TID).addr; \
	}

#define SET_ADDR_EX(DST_ADDR, SRC_TID) \
	if ((SRC_TID).type == AU_IPv4) { \
		if ((SRC_TID).addr[0] != 0) { \
			(DST_ADDR).family = AF_INET; \
			(DST_ADDR).ev_addr = (SRC_TID).addr[0]; \
		} \
	} else if ((SRC_TID).type == AU_IPv6) { \
		(DST_ADDR).family = AF_INET6; \
		(DST_ADDR).ev6_addr[0] = (SRC_TID).addr[0]; \
		(DST_ADDR).ev6_addr[1] = (SRC_TID).addr[1]; \
		(DST_ADDR).ev6_addr[2] = (SRC_TID).addr[2]; \
		(DST_ADDR).ev6_addr[3] = (SRC_TID).addr[3]; \
	}

static bool
auevent_type_in_typelist(const uint16_t type, const uint16_t typelist[]) {
	int i = 0;
	if (!typelist)
		return true;
	while (typelist[i]) {
		if (type == typelist[i])
			return true;
		i++;
	}
	return false;
}

/*
 * ev must be created using auevent_create before every call to
 * auevent_fread and destroyed after using the results.
 *
 * returns 0 to indicate that a record was skipped
 * returns 1 to indicate that a record was read into ev
 * returns -1 on errors
 */
ssize_t
auevent_fread(audit_event_t *ev, const uint16_t aues[], FILE *f) {
	int rv;
	int reclen;
	u_char *recbuf;
	tokenstr_t tok;
	size_t pathc = 0;

	assert(ev);

	/*
	 * https://github.com/openbsm/openbsm/blob/master/libbsm/bsm_io.c
	 *
	 * au_read_rec always reads a whole record.  On read errors or short
	 * reads due to non-blocking I/O, it returns an error and leaves the
	 * file pointer dangling where it was without returning the partially
	 * read buffer.  While using blocking file descriptors on a sane
	 * kernel, this should work for us and read exactly one event from
	 * the file descriptor per call.
	 */
	reclen = au_read_rec(f, &recbuf);
	if (reclen == -1) {
		fprintf(stderr, "au_read_rec(): %s (%i)\n",
		                strerror(errno), errno);
		return -1;
	}
	if (reclen == 0)
		goto skip_rec;

	for (int recpos = 0; recpos < reclen;) {
		rv = au_fetch_tok(&tok, recbuf+recpos, reclen-recpos);
		if (rv == -1) {
			/* partial record; libbsm's current implementation
			 * of au_read_rec never reads a partial record.
			 * If it would, there would be a need for handling
			 * partial records gracefully (praudit does not). */
			fprintf(stderr, "au_fetch_tok() returns error,"
			                " skipping partial record\n");
			goto skip_rec;
		}

		/*
		 * XNU reports subjects and processes not attached to any TTY
		 * with tty device /dev/null and tty addr 0.0.0.0.
		 * Translate those here to no device represented by (dev_t)-1
		 * and no addr represented by address family 0, respectively.
		 */

		switch (tok.id) {
		/* record header and trailer */
		case AUT_HEADER32:
			ev->type = tok.tt.hdr32.e_type;
			if (aues && !auevent_type_in_typelist(ev->type, aues))
				goto skip_rec;
			ev->mod = tok.tt.hdr32.e_mod;
			ev->tv.tv_sec = (time_t)tok.tt.hdr32.s;
			ev->tv.tv_nsec = (long)tok.tt.hdr32.ms*1000000;
			/* size, version */
			break;
		case AUT_HEADER32_EX:
			ev->type = tok.tt.hdr32_ex.e_type;
			if (aues && !auevent_type_in_typelist(ev->type, aues))
				goto skip_rec;
			ev->mod = tok.tt.hdr32_ex.e_mod;
			ev->tv.tv_sec = (time_t)tok.tt.hdr32_ex.s;
			ev->tv.tv_nsec = (long)tok.tt.hdr32_ex.ms*1000000;
			/* size, version */
			break;
		case AUT_HEADER64:
			ev->type = tok.tt.hdr64.e_type;
			if (aues && !auevent_type_in_typelist(ev->type, aues))
				goto skip_rec;
			ev->mod = tok.tt.hdr64.e_mod;
			ev->tv.tv_sec = (time_t)tok.tt.hdr64.s;
			ev->tv.tv_nsec = (long)tok.tt.hdr64.ms;
			/* size, version */
			break;
		case AUT_HEADER64_EX:
			ev->type = tok.tt.hdr64_ex.e_type;
			if (aues && !auevent_type_in_typelist(ev->type, aues))
				goto skip_rec;
			ev->mod = tok.tt.hdr64_ex.e_mod;
			ev->tv.tv_sec = (time_t)tok.tt.hdr64_ex.s;
			ev->tv.tv_nsec = (long)tok.tt.hdr64_ex.ms;
			/* size, version */
			break;
		case AUT_TRAILER:
			/* ignore */
			break;
		/* subject */
		case AUT_SUBJECT32:
			assert(ev->subject_present == 0);
			ev->subject_present = 1;
			ev->subject.auid = tok.tt.subj32.auid;
			ev->subject.euid = tok.tt.subj32.euid;
			ev->subject.egid = tok.tt.subj32.egid;
			ev->subject.ruid = tok.tt.subj32.ruid;
			ev->subject.rgid = tok.tt.subj32.rgid;
			ev->subject.pid = tok.tt.subj32.pid;
			ev->subject.sid = tok.tt.subj32.sid;
			SET_DEV(ev->subject.dev, tok.tt.subj32.tid);
			SET_ADDR(ev->subject.addr, tok.tt.subj32.tid);
			break;
		case AUT_SUBJECT32_EX:
			assert(ev->subject_present == 0);
			ev->subject_present = 1;
			ev->subject.auid = tok.tt.subj32_ex.auid;
			ev->subject.euid = tok.tt.subj32_ex.euid;
			ev->subject.egid = tok.tt.subj32_ex.egid;
			ev->subject.ruid = tok.tt.subj32_ex.ruid;
			ev->subject.rgid = tok.tt.subj32_ex.rgid;
			ev->subject.pid = tok.tt.subj32_ex.pid;
			ev->subject.sid = tok.tt.subj32_ex.sid;
			SET_DEV(ev->subject.dev, tok.tt.subj32_ex.tid);
			SET_ADDR_EX(ev->subject.addr, tok.tt.subj32_ex.tid);
			break;
		case AUT_SUBJECT64:
			assert(ev->subject_present == 0);
			ev->subject_present = 1;
			ev->subject.auid = tok.tt.subj64.auid;
			ev->subject.euid = tok.tt.subj64.euid;
			ev->subject.egid = tok.tt.subj64.egid;
			ev->subject.ruid = tok.tt.subj64.ruid;
			ev->subject.rgid = tok.tt.subj64.rgid;
			ev->subject.pid = tok.tt.subj64.pid;
			ev->subject.sid = tok.tt.subj64.sid;
			SET_DEV(ev->subject.dev, tok.tt.subj64.tid);
			SET_ADDR(ev->subject.addr, tok.tt.subj64.tid);
			break;
		case AUT_SUBJECT64_EX:
			assert(ev->subject_present == 0);
			ev->subject_present = 1;
			ev->subject.auid = tok.tt.subj64_ex.auid;
			ev->subject.euid = tok.tt.subj64_ex.euid;
			ev->subject.egid = tok.tt.subj64_ex.egid;
			ev->subject.ruid = tok.tt.subj64_ex.ruid;
			ev->subject.rgid = tok.tt.subj64_ex.rgid;
			ev->subject.pid = tok.tt.subj64_ex.pid;
			ev->subject.sid = tok.tt.subj64_ex.sid;
			SET_DEV(ev->subject.dev, tok.tt.subj64_ex.tid);
			SET_ADDR_EX(ev->subject.addr, tok.tt.subj64_ex.tid);
			break;
		/* process (as object, other than subject) */
		case AUT_PROCESS32:
			assert(ev->process_present == 0);
			ev->process_present = 1;
			ev->process.auid = tok.tt.proc32.auid;
			ev->process.euid = tok.tt.proc32.euid;
			ev->process.egid = tok.tt.proc32.egid;
			ev->process.ruid = tok.tt.proc32.ruid;
			ev->process.rgid = tok.tt.proc32.rgid;
			ev->process.pid = tok.tt.proc32.pid;
			ev->process.sid = tok.tt.proc32.sid;
			SET_DEV(ev->process.dev, tok.tt.proc32.tid);
			SET_ADDR(ev->process.addr, tok.tt.proc32.tid);
			break;
		case AUT_PROCESS32_EX:
			assert(ev->process_present == 0);
			ev->process_present = 1;
			ev->process.auid = tok.tt.proc32_ex.auid;
			ev->process.euid = tok.tt.proc32_ex.euid;
			ev->process.egid = tok.tt.proc32_ex.egid;
			ev->process.ruid = tok.tt.proc32_ex.ruid;
			ev->process.rgid = tok.tt.proc32_ex.rgid;
			ev->process.pid = tok.tt.proc32_ex.pid;
			ev->process.sid = tok.tt.proc32_ex.sid;
			SET_DEV(ev->process.dev, tok.tt.proc32_ex.tid);
			SET_ADDR_EX(ev->process.addr, tok.tt.proc32_ex.tid);
			break;
		case AUT_PROCESS64:
			assert(ev->process_present == 0);
			ev->process_present = 1;
			ev->process.auid = tok.tt.proc64.auid;
			ev->process.euid = tok.tt.proc64.euid;
			ev->process.egid = tok.tt.proc64.egid;
			ev->process.ruid = tok.tt.proc64.ruid;
			ev->process.rgid = tok.tt.proc64.rgid;
			ev->process.pid = tok.tt.proc64.pid;
			ev->process.sid = tok.tt.proc64.sid;
			SET_DEV(ev->process.dev, tok.tt.proc64.tid);
			SET_ADDR(ev->process.addr, tok.tt.proc64.tid);
			break;
		case AUT_PROCESS64_EX:
			assert(ev->process_present == 0);
			ev->process_present = 1;
			ev->process.auid = tok.tt.proc64_ex.auid;
			ev->process.euid = tok.tt.proc64_ex.euid;
			ev->process.egid = tok.tt.proc64_ex.egid;
			ev->process.ruid = tok.tt.proc64_ex.ruid;
			ev->process.rgid = tok.tt.proc64_ex.rgid;
			ev->process.pid = tok.tt.proc64_ex.pid;
			ev->process.sid = tok.tt.proc64_ex.sid;
			SET_DEV(ev->process.dev, tok.tt.proc64_ex.tid);
			SET_ADDR_EX(ev->process.addr, tok.tt.proc64_ex.tid);
			break;
		/* syscall arguments */
		case AUT_ARG32:
			assert(ev->args[tok.tt.arg32.no].present == 0);
			ev->args[tok.tt.arg32.no].present = 1;
			ev->args[tok.tt.arg32.no].value = tok.tt.arg32.val;
#ifdef DEBUG_AUDITPIPE
			ev->args[tok.tt.arg32.no].text =
				strdup(tok.tt.arg32.text);
			if (!ev->args[tok.tt.arg32.no].text)
				ev->flags |= AEFLAG_ENOMEM;
#endif /* DEBUG_AUDITPIPE */
			ev->args_count = max(ev->args_count,
			                     tok.tt.arg32.no + 1);
			break;
		case AUT_ARG64:
			assert(ev->args[tok.tt.arg64.no].present == 0);
			ev->args[tok.tt.arg64.no].present = 1;
			ev->args[tok.tt.arg64.no].value = tok.tt.arg64.val;
#ifdef DEBUG_AUDITPIPE
			ev->args[tok.tt.arg64.no].text =
				strdup(tok.tt.arg64.text);
			if (!ev->args[tok.tt.arg64.no].text)
				ev->flags |= AEFLAG_ENOMEM;
#endif /* DEBUG_AUDITPIPE */
			ev->args_count = max(ev->args_count,
			                     tok.tt.arg64.no + 1);
			break;
		/* syscall return value */
		case AUT_RETURN32:
			assert(ev->return_present == 0);
			ev->return_present = 1;
			ev->return_error = tok.tt.ret32.status;
			ev->return_value = tok.tt.ret32.ret;
			break;
		case AUT_RETURN64:
			assert(ev->return_present == 0);
			ev->return_present = 1;
			ev->return_error = tok.tt.ret64.err;
			ev->return_value = tok.tt.ret64.val;
			break;
		/* path */
		case AUT_PATH:
			/*
			 * Records for syscalls with a single path argument
			 * should only have a single path token.  However, at
			 * least on 10.11.6, there are two tokens if the path
			 * can be resolved (unresolved and resolved), and one
			 * if it cannot be resolved.  Since there are syscalls
			 * with two path arguments, we store a maximum of four
			 * path arguments.
			 */
			if (!(pathc < sizeof(ev->path)/sizeof(ev->path[0]))) {
				fprintf(stderr, "Too many path tokens, "
				                "skipping record\n");
				goto skip_rec;
			}
			ev->path[pathc] = tok.tt.path.path;
			if (!ev->path[pathc])
				ev->flags |= AEFLAG_ENOMEM;
			pathc++;
			break;
		/* attr */
		case AUT_ATTR32:
			assert(ev->attr_present == 0);
			ev->attr_present = 1;
			ev->attr.mode = tok.tt.attr32.mode;
			ev->attr.uid = tok.tt.attr32.uid;
			ev->attr.gid = tok.tt.attr32.gid;
			ev->attr.dev = tok.tt.attr32.fsid;
			ev->attr.ino = tok.tt.attr32.nid;
			/* ev->attr.rdev = tok.tt.attr32.dev; */
			break;
		case AUT_ATTR64:
			assert(ev->attr_present == 0);
			ev->attr_present = 1;
			ev->attr.mode = tok.tt.attr64.mode;
			ev->attr.uid = tok.tt.attr64.uid;
			ev->attr.gid = tok.tt.attr64.gid;
			ev->attr.dev = tok.tt.attr64.fsid;
			ev->attr.ino = tok.tt.attr64.nid;
			/* ev->attr.rdev = tok.tt.attr64.dev; */
			break;
		/* exec argv */
		case AUT_EXEC_ARGS:
			assert(ev->execarg == NULL);
			if (ev->execarg)
				free(ev->execarg);
			ev->execarg = aev_new(tok.tt.execarg.count,
			                      tok.tt.execarg.text);
			if (!ev->execarg)
				ev->flags |= AEFLAG_ENOMEM;
			break;
		/* exec env */
		case AUT_EXEC_ENV:
			assert(ev->execenv == NULL);
			if (ev->execenv)
				free(ev->execenv);
			ev->execenv = aev_new(tok.tt.execenv.count,
			                      tok.tt.execenv.text);
			if (!ev->execenv)
				ev->flags |= AEFLAG_ENOMEM;
			break;
		/* process exit status */
		case AUT_EXIT:
			assert(ev->exit_present == 0);
			ev->exit_present = 1;
			ev->exit_status = tok.tt.exit.status;
			ev->exit_return = tok.tt.exit.ret;
			break;
		/* unhandled tokens */
		default:
			for (int i = 0; i < 256; i++) {
				if (ev->unk_tokids[i] == tok.id)
					break;
				if (ev->unk_tokids[i] == 0) {
					ev->unk_tokids[i] = tok.id;
					break;
				}
			}
			break;
		}

#ifdef DEBUG_AUDITPIPE
		au_print_flags_tok(stderr, &tok, ":", AU_OFLAG_NONE);
		fprintf(stderr, "\n");
#endif
		recpos += tok.len;
	}

	free(recbuf);
	return (ev->flags & AEFLAG_ENOMEM) ? -1 : 1;

skip_rec:
	free(recbuf);
	return 0;
}

void
auevent_fprint(FILE *f, audit_event_t *ev) {
	struct au_event_ent *aue_ent;

	assert(ev);
	aue_ent = getauevnum(ev->type);
	fprintf(f, "%s [%i:%i] @%li.%09li", aue_ent->ae_name, ev->type, ev->mod,
	        ev->tv.tv_sec, ev->tv.tv_nsec);
	if (ev->subject_present) {
		fprintf(f,
		        " subject_pid=%i"
		        " subject_sid=%"PRIu32
		        " subject_tid=/dev/%s[%s]"
		        " subject_auid=%u"
		        " subject_euid=%u"
		        " subject_egid=%u"
		        " subject_ruid=%u"
		        " subject_rgid=%u",
		        ev->subject.pid,
		        ev->subject.sid,
		        sys_ttydevname(ev->subject.dev),
		        ipaddrtoa(&ev->subject.addr, "n/a"),
		        ev->subject.auid,
		        ev->subject.euid,
		        ev->subject.egid,
		        ev->subject.ruid,
		        ev->subject.rgid);
	}
	if (ev->process_present) {
		fprintf(f,
		        " process_pid=%i"
		        " process_sid=%"PRIu32
		        " process_tid=/dev/%s[%s]"
		        " process_auid=%u"
		        " process_euid=%u"
		        " process_egid=%u"
		        " process_ruid=%u"
		        " process_rgid=%u",
		        ev->process.pid,
		        ev->process.sid,
		        sys_ttydevname(ev->process.dev),
		        ipaddrtoa(&ev->process.addr, "n/a"),
		        ev->process.auid,
		        ev->process.euid,
		        ev->process.egid,
		        ev->process.ruid,
		        ev->process.rgid);
	}
	for (int i = 0; i < ev->args_count; i++) {
		if (ev->args[i].present) {
#ifdef DEBUG_AUDITPIPE
			fprintf(f, " args[%i:%s]=%"PRIu64, i,
			        ev->args[i].text,
			        ev->args[i].value);
#else
			fprintf(f, " args[%i]=%"PRIu64, i,
			        ev->args[i].value);
#endif
		}
	}
	if (ev->return_present) {
		fprintf(f, " return_error=%u return_value=%"PRIu32,
		        ev->return_error, ev->return_value);
	}
	if (ev->exit_present) {
		fprintf(f, " exit_status=%"PRIu32" exit_return=%"PRIu32,
		        ev->exit_status, ev->exit_return);
	}
	for (size_t i = 0; i < sizeof(ev->path)/sizeof(ev->path[0]); i++) {
		if (ev->path[i]) {
			fprintf(f, " path[%zu]='%s'", i, ev->path[i]);
		}
	}
	if (ev->attr_present) {
		fprintf(f, " attr_mode=%o attr_uid=%u attr_gid=%u",
		        ev->attr.mode,
		        ev->attr.uid,
		        ev->attr.gid);
	}
	if (ev->execarg) {
		fprintf(f, " execarg");
		for (size_t i = 0; ev->execarg[i]; i++) {
			fprintf(f, "%s'%s'", i ? " ": "=",
			        ev->execarg[i]);
		}
	}
	if (ev->execenv) {
		fprintf(f, " execenv");
		for (size_t i = 0; ev->execenv[i]; i++) {
			fprintf(f, "%s'%s'", i ? " ": "=",
			        ev->execenv[i]);
		}
	}
	if (ev->unk_tokids[0]) {
		fprintf(f, " unk_tokids");
		for (int i = 0; i < 256; i++) {
			if (ev->unk_tokids[i] == 0)
				break;
			fprintf(f, "%s0x%02x", i ? "," : "=",
			        ev->unk_tokids[i]);
		}
	}
	fprintf(f, "\n");
}

void
auevent_create(audit_event_t *ev) {
	assert(ev);
	bzero(ev, sizeof(audit_event_t));
}

void
auevent_destroy(audit_event_t *ev) {
	/* free raw event memory */
	if (ev->execarg) {
		free(ev->execarg);
		ev->execarg = NULL;
	}
	if (ev->execenv) {
		free(ev->execenv);
		ev->execenv = NULL;
	}
#ifdef DEBUG_AUDITPIPE
	for (int i = 0; i < ev->args_count; i++) {
		if (ev->args[i].present && ev->args[i].text) {
			free(ev->args[i].text);
			ev->args[i].text = NULL;
		}
	}
#endif /* DEBUG_AUDITPIPE */
}

