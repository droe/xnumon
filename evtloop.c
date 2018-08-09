/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include "evtloop.h"

#include "auclass.h"
#include "auevent.h"
#include "aupolicy.h"
#include "sys.h"
#include "str.h"
#include "time.h"
#include "os.h"
#include "policy.h"
#include "debug.h"
#include "attrib.h"

#include <stdint.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>

static bool running = true;     /* shared */
static int kefd = -1;           /* shared */
static FILE *auef = NULL;
static pid_t xnumon_pid;
static uint64_t aupclobbers = 0;
static uint64_t aueunknowns = 0;
static uint64_t failedsyscalls = 0;
static uint64_t radar38845422 = 0;
static uint64_t radar38845422_fatal = 0;
static uint64_t radar38845784 = 0;
static uint64_t radar39267328 = 0;
static uint64_t radar39267328_fatal = 0;
static uint64_t radar39623812 = 0;
static uint64_t radar39623812_fatal = 0;
static uint64_t radar42770257_fatal = 0;
static uint64_t radar42783724 = 0;
static uint64_t radar42783724_fatal = 0;
static uint64_t radar42784847 = 0;
static uint64_t radar42784847_fatal = 0;
static uint64_t radar42946744_fatal = 0;
static uint64_t missingtoken = 0;
static uint64_t ooms = 0;

static bool kextloop_running = true;
static pthread_t kextloop_thr;

static int
kefd_readable(int fd, UNUSED void *udata) {
	const xnumon_msg_t *msg;
	struct timespec tm;

	msg = kextctl_recv(fd);
	if (!msg)
		return -1;
	tm.tv_sec = msg->time_s;
	tm.tv_nsec = msg->time_ns;
	procmon_kern_preexec(&tm, (pid_t)msg->pid, msg->path);
	if (kextctl_ack(fd, msg) == -1) {
		fprintf(stderr, "Failed to acknowledge message from kext\n");
		return -1;
	}
	return 0;
}

static void *
kextloop_thread(void *arg) {
	kqueue_t *kq = (kqueue_t *)arg;

#if 0	/* terra pericolosa */
	(void)policy_thread_sched_priority(TP_HIGH);
#endif
	(void)policy_thread_diskio_important();

	/* event dispatch loop */
	kextloop_running = true;
	for (;;) {
		int rv = kqueue_dispatch(kq);
		if (!kextloop_running)
			break;
		if (rv != 0) {
			fprintf(stderr, "kevent_dispatch() failed\n");
			running = false; /* stop main loop */
			break;
		}
	}

	kqueue_free(kq);
	close(kefd);
	kefd = -1;
	return NULL;
}

static void
kextloop_break(void) {
	kextloop_running = false;
	if (pthread_join(kextloop_thr, NULL) != 0) {
		fprintf(stderr, "Failed to join kextloop thread - exiting\n");
		exit(EXIT_FAILURE);
	}
}

static int
kextloop_spawn(kevent_ctx_t *ctx) {
	kqueue_t *kq = NULL;

	if ((kefd = kextctl_open()) == -1) {
		fprintf(stderr, "kextctl_open() failed: %s (%i)\n",
		        strerror(errno), errno);
		goto errout;
	}
	/* from here on the kernel blocks execs until we ACK */

	kq = kqueue_new();
	if (!kq) {
		fprintf(stderr, "kqueue_new() failed: %s (%i)\n",
		                strerror(errno), errno);
		goto errout;
	}

	if (kqueue_add_fd_read(kq, kefd, ctx) == -1) {
		fprintf(stderr, "kqueue_add_fd_read(/dev/xnumon) failed: "
		                "%s (%i)\n", strerror(errno), errno);
		goto errout;
	}

	if (pthread_create(&kextloop_thr, NULL, kextloop_thread, kq) != 0) {
		fprintf(stderr, "pthread_create() failed: "
		                "%s (%i)\n", strerror(errno), errno);
		goto errout;
	}
	return 0;

errout:
	if (kq) {
		kqueue_free(kq);
	}
	if (kefd != -1) {
		close(kefd);
		kefd = -1;
	}
	return -1;
}

/*
 * Called when the auditpipe file descriptor is readable.
 *
 * XNU BSD syscalls:
 * https://github.com/apple/darwin-xnu/blob/master/bsd/kern/syscalls.master
 * XNU Mach syscalls:
 * https://github.com/apple/darwin-xnu/blob/master/osfmk/mach/syscall_sw.h
 *
 * Mostly complete workarounds for the following bugs in audit(4):
 * 38845422: audit(4): nonsensical path and missing attr for posix_spawn(2)
 * 38845784: audit(4): spurious return value for execve(2)
 * 39267328: audit(4): target path not resolved for rename(2)
 * 39623812: audit(4): path not resolved for utimes(2)
 * 42783724: audit(4): target path not resolved for link(2)
 * 42784847: audit(4): path not resolved for symlink(2)
 * 43063872: audit(4): port in wrong byte order for ports on IPv6 sockets
 *
 * Partial workarounds for the following audit(4) bugs:
 * 42770257: audit(4): only one/two instead of 4 path tokens for renameat(2)
 *
 * Only detection, no workaround for the following bugs in audit(4):
 * 42946744: audit(4): missing argv and arge for __mac_execve(2)
 *
 * Neither detection nor workaround for the following bugs in audit(4):
 * 40755284: audit(4): processor_set_tasks() cannot be audited
 * 43006946: audit(4): no AUE_CONNECT for connect(2) on non-blocking socket
 *
 * Presence of bugs without workaround can be detected using the test suite.
 */
#define TOKEN_ASSERT(EVENT, TOKEN, COND) \
	if (!(COND)) { \
		missingtoken++; \
		DEBUG(cfg->debug, "missingtoken", \
		      "event=" EVENT " token=" TOKEN); \
		if (cfg->debug) \
			auevent_fprint(stderr, &ev); \
		break; \
	}
static int
auef_readable(UNUSED int fd, void *udata) {
	config_t *cfg = (config_t *)udata;
	audit_event_t ev;
	const char *cwd;
	char *path;
	int rv;

	auevent_create(&ev);
	rv = auevent_fread(&ev, NULL, cfg->envlevel /* HACK */, auef);
	if (rv == -1 || rv == 0) {
		if (ev.flags & AEFLAG_ENOMEM)
			ooms++;
		auevent_destroy(&ev);
		return rv;
	}

#ifdef DEBUG_AUDITPIPE
	auevent_fprint(stderr, &ev);
#endif

	/* avoid reacting on our own close invocations */
	if (ev.subject.pid == xnumon_pid)
		goto out;

	switch (ev.type) {

	/*
	 * Events for process monitoring.
	 */

	case AUE_FORK:
	case AUE_VFORK:
		TOKEN_ASSERT("fork", "return", ev.return_present);
		if (ev.return_value > INT_MAX) {
			failedsyscalls++;
			break;
		}
		TOKEN_ASSERT("fork", "subject", ev.subject_present);
		procmon_fork(&ev.tv, &ev.subject, ev.return_value);
		break;

	case AUE_POSIX_SPAWN:
		TOKEN_ASSERT("posix_spawn", "return", ev.return_present);
		if (ev.return_value) {
			/* posix_spawnp spams an event for each directory in
			 * $PATH with return_value==2 until it finds the actual
			 * matching executable (10.11.6) */
			failedsyscalls++;
			break;
		}
		TOKEN_ASSERT("posix_spawn", "subject", ev.subject_present);
		/*
		 * On at least 10.11.6 and 10.12.6, the following happens:
		 * path is /dev/console when launchd spawns xpcproxy,
		 * path is /dev/null when xpcproxy execs the XPC target,
		 * path is $CWD/dev/ttysNNN when lldb spawns debug subject;
		 * in all of these cases, no attr token is provided, and there
		 * is only one path instead of two.
		 *
		 * Reported to Apple as radar 38845422 on 2018-03-25.
		 *
		 * As a result, whenever no attr is present or path starts in
		 * /dev, assume a buggy path.  First try the path by pid.
		 * If that fails, employ less reliable ways to work around the
		 * issue.
		 */
		path = (char *)(ev.path[1] ? ev.path[1] : ev.path[0]);
		if (ev.attr_count == 0 || !path ||
		    !str_beginswith(path, "/dev/")) {
			radar38845422++;
			path = sys_pidpath(ev.args[0].present ?
			                   ev.args[0].value : ev.subject.pid);
			if (!path) {
				if (!ev.execarg) {
					radar38845422_fatal++;
					DEBUG(cfg->debug,
					      "radar38845422_fatal",
					      "path[0]=%s "
					      "path[1]=%s "
					      "args[0]=%i "
					      "pid=%i "
					      "sys_pidpath(args[0]||pid)=>%s",
					      ev.path[0],
					      ev.path[1],
					      ev.args[0].present
					      ? (int)ev.args[0].value : -1,
					      ev.subject.pid,
					      cwd);
					break;
				}
				/* When launchd spawns the xpcproxy exec
				 * trampoline, path is /dev/console and argv[0]
				 * is just xpcproxy; hardcode that.
				 * This allows a malicious binary to be named
				 * xpcproxy and triggering this kernel bug to
				 * hide its hash and codesigning status from
				 * us unless kextlevel >= 1. */
				if (!strcmp(ev.execarg[0], "xpcproxy")) {
					path = strdup("/usr/libexec/xpcproxy");
				} else {
					/* As a last resort, use execarg[0] as
					 * path; note that this is not always
					 * absolute, can be just the basename;
					 * also it is forgeable.
					 * If we are using the kext, the real
					 * path will be fetched from the kext.
					 * If not, there will be no way to
					 * reliably find the corresponding
					 * image on disk. */
					path = strdup(ev.execarg[0]);
				}
				if (!path)
					ooms++;
			}
		} else {
			path = strdup(path);
			if (!path)
				ooms++;
		}
		if (!path)
			/* got counted above */
			break;
		if (!ev.args[0].present) {
			/* POSIX_SPAWN_SETEXEC */
			procmon_exec(&ev.tv,
			             &ev.subject,
			             path,
			             ev.attr_count > 0 ? &ev.attr[0] : NULL,
			             ev.execarg,
			             ev.execenv);
			ev.execarg = NULL; /* pass ownership to procmon */
			ev.execenv = NULL; /* pass ownership to procmon */
			break;
		}
		TOKEN_ASSERT("execve", "args[0]", ev.args[0].present);
		procmon_spawn(&ev.tv,
		              &ev.subject,
		              ev.args[0].value,
		              path,
		              ev.attr_count > 0 ? &ev.attr[0] : NULL,
		              ev.execarg,
		              ev.execenv);
		ev.execarg = NULL; /* pass ownership to procmon */
		ev.execenv = NULL; /* pass ownership to procmon */
		break;

	case AUE_EXEC:
	case AUE_EXECVE:
	case AUE_MAC_EXECVE:
		TOKEN_ASSERT("execve", "subject", ev.subject_present);
		/*
		 * On at least 10.11.6, audit records for successful execve
		 * invocations sometimes have a pid as return value, for
		 * example when being spawned from make, which does not
		 * indicate failure; only treat negative values as errors.
		 *
		 * Reported to Apple as radar 38845784 on 2018-03-25.
		 */
		if (ev.return_present) {
			if (ev.return_value > INT_MAX) {
				failedsyscalls++;
				break;
			} else if (ev.return_value != 0) {
				radar38845784++;
			}
		}
		TOKEN_ASSERT("execve", "path", ev.path[0]);
		path = (char *)(ev.path[1] ? ev.path[1] : ev.path[0]);
		assert(path);
		path = strdup(path);
		if (!path) {
			ooms++;
			break;
		}
		if (ev.type == AUE_MAC_EXECVE && (
		    !ev.execarg || ((cfg->envlevel > 0) && !ev.execenv))) {
			/*
			 * On at least 10.11.6, audit records for __mac_execve
			 * are missing their exec arg and exec env tokens.
			 *
			 * Reported to Apple as radar 42946744 on 2018-08-05.
			 */
			radar42946744_fatal++;
			DEBUG(cfg->debug,
			      "radar42946744_fatal",
			      "path[0]=%s "
			      "path[1]=%s "
			      "argv=%i env=%i "
			      "pid=%i",
			      ev.path[0],
			      ev.path[1],
			      ev.execarg ? 1 : 0,
			      ev.execenv ? 1 : 0,
			      ev.subject.pid);
		}
		procmon_exec(&ev.tv,
		             &ev.subject,
		             path,
		             ev.attr_count > 0 ? &ev.attr[0] : NULL,
		             ev.execarg,
		             ev.execenv);
		ev.execarg = NULL; /* pass ownership to procmon */
		ev.execenv = NULL; /* pass ownership to procmon */
		break;

	case AUE_EXIT:
		TOKEN_ASSERT("exit", "subject", ev.subject_present);
		/* exit never fails; audit event not triggered if process got
		 * terminated in other ways than calling exit() */
		procmon_exit(&ev.tv, ev.subject.pid);
		break;

	case AUE_WAIT4:
		TOKEN_ASSERT("wait4", "return", ev.return_present);
		if (ev.return_value == 0 || ev.return_value > INT_MAX) {
			failedsyscalls++;
			break;
		}
		/* cannot distinguish terminated and stopped processes */
		procmon_wait4(&ev.tv, ev.return_value);
		break;

	case AUE_CHDIR:
	case AUE_FCHDIR:
		TOKEN_ASSERT("chdir", "return", ev.return_present);
		if (ev.return_value) {
			failedsyscalls++;
			break;
		}
		TOKEN_ASSERT("chdir", "subject", ev.subject_present);
		TOKEN_ASSERT("chdir", "path", ev.path[0]);
		path = (char *)(ev.path[1] ? ev.path[1] : ev.path[0]);
		assert(path);
		path = strdup(path);
		if (!path) {
			ooms++;
			break;
		}
		procmon_chdir(&ev.tv, ev.subject.pid, path);
		break;

	/*
	 * Events for tracking inter-process access commonly used for
	 * code injection and other manipulation.
	 */

	case AUE_TASKFORPID:
		if (!LOGEVT_WANT(cfg->events, LOGEVT_HACKMON))
			break;
		TOKEN_ASSERT("task_for_pid", "return", ev.return_present);
		if (ev.return_value) {
			failedsyscalls++;
			break;
		}
		TOKEN_ASSERT("task_for_pid", "subject", ev.subject_present);
		/* The PROCESS_PID_TOKENS macro in XNU creates a process token
		 * from pid arg 2 only if pid > 0. */
		TOKEN_ASSERT("task_for_pid", "process",
		             ev.process_present || ev.args[2].present);
		hackmon_taskforpid(&ev.tv, &ev.subject,
		                   ev.process_present ? &ev.process : NULL,
		                   ev.args[2].present ? ev.args[2].value : -1);
		break;

	case AUE_PTRACE:
		if (!LOGEVT_WANT(cfg->events, LOGEVT_HACKMON))
			break;
		TOKEN_ASSERT("ptrace", "return", ev.return_present);
		if (ev.return_value) {
			failedsyscalls++;
			break;
		}
		TOKEN_ASSERT("ptrace", "subject", ev.subject_present);
		/* The PROCESS_PID_TOKENS macro in XNU creates a process token
		 * from pid arg 2 only if pid > 0. */
		TOKEN_ASSERT("ptrace", "process",
		             ev.process_present || ev.args[2].present);
		hackmon_ptrace(&ev.tv, &ev.subject,
		               ev.process_present ? &ev.process : NULL,
		               ev.args[2].present ? ev.args[2].value : -1);
		break;

	/*
	 * Events for tracking file modifications.
	 */

	case AUE_OPEN_W:
	case AUE_OPEN_WC:
	case AUE_OPEN_WT:
	case AUE_OPEN_WTC:
	case AUE_OPEN_RW:
	case AUE_OPEN_RWC:
	case AUE_OPEN_RWT:
	case AUE_OPEN_RWTC:
	case AUE_OPEN_EXTENDED_W:
	case AUE_OPEN_EXTENDED_WC:
	case AUE_OPEN_EXTENDED_WT:
	case AUE_OPEN_EXTENDED_WTC:
	case AUE_OPEN_EXTENDED_RW:
	case AUE_OPEN_EXTENDED_RWC:
	case AUE_OPEN_EXTENDED_RWT:
	case AUE_OPEN_EXTENDED_RWTC:
	case AUE_OPENAT_W:
	case AUE_OPENAT_WC:
	case AUE_OPENAT_WT:
	case AUE_OPENAT_WTC:
	case AUE_OPENAT_RW:
	case AUE_OPENAT_RWC:
	case AUE_OPENAT_RWT:
	case AUE_OPENAT_RWTC:
	case AUE_OPENBYID_W:
	case AUE_OPENBYID_WT:
	case AUE_OPENBYID_RW:
	case AUE_OPENBYID_RWT:
		if (!LOGEVT_WANT(cfg->events, LOGEVT_FILEMON))
			break;
		TOKEN_ASSERT("open(w)", "return", ev.return_present);
		if (ev.return_value > INT_MAX) {
			failedsyscalls++;
			break;
		}
		TOKEN_ASSERT("open(w)", "subject", ev.subject_present);
#if 0
		TOKEN_ASSERT("open(w)", "arg[2](flags)", ev.args[2].present);
		TOKEN_ASSERT("open(w)", "arg[3](mode)", ev.args[3].present);
#endif
		TOKEN_ASSERT("open(2)", "path[0]", ev.path[0]);
		/* sometimes one, sometimes two path tokens, unsure if bug */
		path = (char *)(ev.path[1] ? ev.path[1] : ev.path[0]);
		assert(path);
		procmon_file_open(&ev.subject, ev.return_value, path);
		break;

	case AUE_CLOSE:
		if (!LOGEVT_WANT(cfg->events, LOGEVT_FILEMON|LOGEVT_SOCKMON))
			break;
		TOKEN_ASSERT("close", "return", ev.return_present);
		if (ev.return_value) {
			failedsyscalls++;
			break;
		}
		TOKEN_ASSERT("close", "subject", ev.subject_present);
		TOKEN_ASSERT("close", "arg[2](fd)", ev.args[2].present);
		procmon_fd_close(ev.subject.pid, ev.args[2].value);
		if (!LOGEVT_WANT(cfg->events, LOGEVT_FILEMON))
			break;
		if (!ev.path[0]) {
			/* closed file descriptor does not point to vnode */
			break;
		}
		path = (char *)(ev.path[1] ? ev.path[1] : ev.path[0]);
		assert(path);
		path = strdup(path);
		if (!path) {
			ooms++;
			break;
		}
		filemon_touched(&ev.tv, &ev.subject, path);
		break;

	case AUE_UTIMES:
	case AUE_FUTIMES:
		if (!LOGEVT_WANT(cfg->events, LOGEVT_FILEMON))
			break;
		TOKEN_ASSERT("utimes", "return", ev.return_present);
		if (ev.return_value) {
			failedsyscalls++;
			break;
		}
		TOKEN_ASSERT("utimes", "subject", ev.subject_present);
		/*
		 * On at least 10.11.6, records include only an unresolved
		 * path.
		 *
		 * Reported to Apple as radar 39623812 on 2018-04-21.
		 */
		if (ev.path[1]) {
			/* two path tokens */
			path = strdup(ev.path[1]);
			if (!path)
				ooms++;
		} else if (ev.path[0]) {
			/* one path token, assume unresolved if no attr */
			if (ev.attr_count > 0) {
				path = strdup(ev.path[0]);
				if (!path)
					ooms++;
			} else {
				radar39623812++;
				cwd = procmon_getcwd(ev.subject.pid, &ev.tv);
				if (!cwd && (errno == ENOMEM))
					ooms++;
				path = sys_realpath(ev.path[0], cwd);
				if (!path) {
					if (errno == ENOMEM)
						ooms++;
					else {
						radar39623812_fatal++;
						DEBUG(cfg->debug,
						      "radar39623812_fatal",
						      "path[0]=%s "
						      "pid=%i "
						      "procmon_getcwd(pid)=>%s",
						      ev.path[0],
						      ev.subject.pid,
						      cwd);
					}
				}
			}
		} else {
			path = NULL;
			missingtoken++;
			DEBUG(cfg->debug, "missingtoken",
			      "event=utimes token=path");
			if (cfg->debug)
				auevent_fprint(stderr, &ev);
		}
		if (!path)
			/* counted above */
			break;
		filemon_touched(&ev.tv, &ev.subject, path);
		break;

	case AUE_RENAME:
	case AUE_RENAMEAT:
	case AUE_LINK:
	case AUE_LINKAT:
	case AUE_CLONEFILEAT:
	case AUE_FCLONEFILEAT:
	case AUE_COPYFILE:
		/* FIXME handle copyfile separately in order to be able to
		 * handle all the corner cases like recursive copying */
		if (!LOGEVT_WANT(cfg->events, LOGEVT_FILEMON))
			break;
		TOKEN_ASSERT("rename|link|clonefile|copyfile",
		             "return", ev.return_present);
		if (ev.return_value) {
			failedsyscalls++;
			break;
		}
		TOKEN_ASSERT("rename|link|clonefile|copyfile",
		             "subject", ev.subject_present);
		/*
		 * On at least 10.11.6, AUE_RENAME and AUE_LINK records
		 * include only an unresolved target path.
		 *
		 * Reported to Apple as radar 39267328 on 2018-04-08 and
		 * radar 42783724 on 2018-07-31 respectively.
		 */
		if (ev.path[3]) {
			/* four path tokens, as expected */
			path = strdup(ev.path[3]);
			if (!path)
				ooms++;
		} else if (ev.path[2] && !ev.path[3]) {
			/* three path tokens, assume third unresolved dpath */
			if (ev.type == AUE_RENAME) {
				radar39267328++;
			} else if (ev.type == AUE_LINK) {
				radar42783724++;
			} else {
				missingtoken++;
				DEBUG(cfg->debug, "missingtoken",
				      "event=rename|link|clonefile|copyfile "
				      "token=path");
				if (cfg->debug)
					auevent_fprint(stderr, &ev);
			}
			cwd = procmon_getcwd(ev.subject.pid, &ev.tv);
			if (!cwd && (errno == ENOMEM))
				ooms++;
			path = sys_realpath(ev.path[2], cwd);
			if (!path) {
				if (errno == ENOMEM)
					ooms++;
				else if (ev.type == AUE_RENAME) {
					radar39267328_fatal++;
					DEBUG(cfg->debug,
					      "radar39267328_fatal",
					      "path[2]=%s "
					      "pid=%i "
					      "procmon_getcwd(pid)=>%s",
					      ev.path[2],
					      ev.subject.pid,
					      cwd);
				} else if (ev.type == AUE_LINK) {
					radar42783724_fatal++;
					DEBUG(cfg->debug,
					      "radar42783724_fatal",
					      "path[2]=%s "
					      "pid=%i "
					      "procmon_getcwd(pid)=>%s",
					      ev.path[2],
					      ev.subject.pid,
					      cwd);
				}
			}
		} else {
			/* less than three path tokens */
			path = NULL;
			if (ev.type == AUE_RENAMEAT) {
				/*
				 * AUE_RENAMEAT records sometimes have only one
				 * or two path tokens instead of four.
				 *
				 * Reported to Apple as radar 42770257 on
				 * 2018-07-31.
				 */
				radar42770257_fatal++;
				DEBUG(cfg->debug, "radar42770257_fatal",
				      "event=renameat token=path");
			} else {
				missingtoken++;
				DEBUG(cfg->debug, "missingtoken",
				      "event=rename|link token=path");
			}
			if (cfg->debug)
				auevent_fprint(stderr, &ev);
		}
		if (!path)
			/* counted above */
			break;
		filemon_touched(&ev.tv, &ev.subject, path);
		break;

	case AUE_SYMLINK:
	case AUE_SYMLINKAT:
		if (!LOGEVT_WANT(cfg->events, LOGEVT_FILEMON))
			break;
		TOKEN_ASSERT("symlink", "return", ev.return_present);
		if (ev.return_value) {
			failedsyscalls++;
			break;
		}
		TOKEN_ASSERT("symlink", "subject", ev.subject_present);
		/*
		 * On at least 10.11.6, AUE_SYMLINK records include only an
		 * unresolved target path.
		 *
		 * Reported to Apple as radar 42784847 on 2018-07-31.
		 */
		if (ev.path[1]) {
			path = strdup(ev.path[1]);
			if (!path)
				ooms++;
		} else if (ev.path[0] && !ev.path[1]) {
			/* only an unresolved target path token */
			radar42784847++;
			cwd = procmon_getcwd(ev.subject.pid, &ev.tv);
			if (!cwd && (errno == ENOMEM))
				ooms++;
			path = sys_realpath(ev.path[0], cwd);
			if (!path) {
				if (errno == ENOMEM)
					ooms++;
				else {
					radar42784847_fatal++;
					DEBUG(cfg->debug,
					      "radar42784847_fatal",
					      "path[0]=%s "
					      "pid=%i "
					      "procmon_getcwd(pid)=>%s",
					      ev.path[0],
					      ev.subject.pid,
					      cwd);
				}
			}
		} else {
			path = NULL;
			missingtoken++;
			DEBUG(cfg->debug, "missingtoken",
			      "event=symlink token=path");
			if (cfg->debug)
				auevent_fprint(stderr, &ev);
		}
		if (!path)
			/* counted above */
			break;
		filemon_touched(&ev.tv, &ev.subject, path);
		break;

	/*
	 * Events for socket tracking.
	 */

	case AUE_SOCKET:
		if (!LOGEVT_WANT(cfg->events, LOGEVT_SOCKMON))
			break;
		TOKEN_ASSERT("socket", "return", ev.return_present);
		if (ev.return_value > INT_MAX) {
			failedsyscalls++;
			break;
		}
		TOKEN_ASSERT("socket", "subject", ev.subject_present);
		TOKEN_ASSERT("socket", "arg[1](domain)", ev.args[1].present);
		TOKEN_ASSERT("socket", "arg[2](type)", ev.args[2].present);
		TOKEN_ASSERT("socket", "arg[3](protocol)", ev.args[3].present);
		sockmon_socket(&ev.tv, &ev.subject, ev.return_value,
		               auevent_sock_domain(ev.args[1].value),
		               auevent_sock_type(ev.args[2].value),
		               ev.args[3].value);
		break;

	case AUE_BIND:
		if (!LOGEVT_WANT(cfg->events, LOGEVT_SOCKMON))
			break;
		TOKEN_ASSERT("bind", "return", ev.return_present);
		if (ev.return_value != 0) {
			failedsyscalls++;
			break;
		}
		if (!ev.sockinet_present)
			/* skip unix socket */
			break;
		TOKEN_ASSERT("bind", "subject", ev.subject_present);
		TOKEN_ASSERT("bind", "arg[1](fd)", ev.args[1].present);
		sockmon_bind(&ev.tv, &ev.subject, ev.args[1].value,
		             &ev.sockinet_addr, ev.sockinet_port);
		break;

	case AUE_LISTEN:
		if (!LOGEVT_WANT(cfg->events,
		                 LOGEVT_FLAG(LOGEVT_SOCKET_LISTEN)))
			break;
		TOKEN_ASSERT("listen", "return", ev.return_present);
		if (ev.return_value != 0) {
			failedsyscalls++;
			break;
		}
		TOKEN_ASSERT("listen", "subject", ev.subject_present);
		TOKEN_ASSERT("listen", "arg[1](fd)", ev.args[1].present);
		sockmon_listen(&ev.tv, &ev.subject, ev.args[1].value);
		break;

	case AUE_ACCEPT:
		if (!LOGEVT_WANT(cfg->events,
		                 LOGEVT_FLAG(LOGEVT_SOCKET_ACCEPT)))
			break;
		TOKEN_ASSERT("accept", "return", ev.return_present);
		if (ev.return_value > INT_MAX) {
			failedsyscalls++;
			break;
		}
		if (!ev.sockinet_present)
			/* skip unix socket */
			break;
		TOKEN_ASSERT("accept", "subject", ev.subject_present);
		TOKEN_ASSERT("accept", "arg[1](fd)", ev.args[1].present);
		sockmon_accept(&ev.tv, &ev.subject, ev.args[1].value,
		               &ev.sockinet_addr, ev.sockinet_port);
		break;

	case AUE_CONNECT:
		if (!LOGEVT_WANT(cfg->events,
		                 LOGEVT_FLAG(LOGEVT_SOCKET_CONNECT)))
			break;
		/* While it would be interesting to see failed connects,
		 * XNU does not seem to provide audit(4) records for them. */
		TOKEN_ASSERT("connect", "return", ev.return_present);
		if (ev.return_value != 0) {
			failedsyscalls++;
			break;
		}
		if (!ev.sockinet_present)
			/* unix socket */
			break;
		TOKEN_ASSERT("connect", "subject", ev.subject_present);
		TOKEN_ASSERT("connect", "arg[1](fd)", ev.args[1].present);
		sockmon_connect(&ev.tv, &ev.subject, ev.args[1].value,
		                &ev.sockinet_addr, ev.sockinet_port);
		break;

	/*
	 * Unhandled events.
	 */

	default:
		/*
		 * Some event types seem to be logged regardless of the class
		 * mask settings.  However, their volume seems to be low, so
		 * far only userspace events have been seen (10.11.6), so we
		 * just ignore them here instead of filtering on each event.
		 */
#ifdef DEBUG_AUDITPIPE
		fprintf(stderr, "Unhandled event type=%u\n", ev.type);
#endif
		aueunknowns++;
		break;
	}

out:
	auevent_destroy(&ev); /* free all allocated members not NULLed above */
	return 0;
}
#undef TOKEN_ASSERT

/*
 * Handles SIGTERM, SIGQUIT and SIGINT.
 */
static int
sigquit_arrived(UNUSED int sig, UNUSED void *udata) {
	running = false;
	fprintf(stderr, "Shutting down, draining queues...\n");
	return -1; /* stop processing more events */
}

/*
 * Handles SIGTSTP.
 */
static int
sigtstp_arrived(UNUSED int sig, UNUSED void *udata) {
	fprintf(stderr, "Cannot stop while attached to kext cdev\n");
	return 0;
}

void
evtloop_stats(evtloop_stat_t *st) {
	if (kefd != -1) {
		kextctl_stats(kefd, &st->ke);
	}
	procmon_stats(&st->pm);
	hackmon_stats(&st->hm);
	filemon_stats(&st->fm);
	sockmon_stats(&st->sm);
	st->el_aupclobbers = aupclobbers;
	st->el_aueunknowns = aueunknowns;
	st->el_failedsyscalls = failedsyscalls;
	st->el_radar38845422_fatal = radar38845422_fatal;
	st->el_radar38845422 = radar38845422;
	st->el_radar38845784 = radar38845784;
	st->el_radar39623812_fatal = radar39623812_fatal;
	st->el_radar39623812 = radar39623812;
	st->el_radar39267328_fatal = radar39267328_fatal;
	st->el_radar39267328 = radar39267328;
	st->el_radar42770257_fatal = radar42770257_fatal;
	st->el_radar42770257 = radar42770257_fatal;
	st->el_radar42783724_fatal = radar42783724_fatal;
	st->el_radar42783724 = radar42783724;
	st->el_radar42784847_fatal = radar42784847_fatal;
	st->el_radar42784847 = radar42784847;
	st->el_radar42946744_fatal = radar42946744_fatal;
	st->el_radar42946744 = radar42946744_fatal;
	st->el_missingtoken = missingtoken;
	st->el_ooms = ooms;
	aupipe_stats(fileno(auef), &st->ap);
	work_stats(&st->wq);
	log_stats(&st->lq);
	cachehash_stats(&st->ch);
	cachecsig_stats(&st->cc);
	cacheldpl_stats(&st->cl);
}

/*
 * Handles SIGINFO.
 */
static int
siginfo_arrived(UNUSED int sig, UNUSED void *udata) {
	evtloop_stat_t st;

	evtloop_stats(&st);

	fprintf(stderr, "evtloop "
	                "aupclobber:%"PRIu64" "
	                "aueunknown:%"PRIu64" "
	                "failedsyscalls:%"PRIu64" "
	                "missingtoken:%"PRIu64" "
	                "oom:%"PRIu64"\n        "
	                "r38845422:%"PRIu64"/%"PRIu64" "
	                "r38845784:0/%"PRIu64" "
	                "r39267328:%"PRIu64"/%"PRIu64" "
	                "r39623812:%"PRIu64"/%"PRIu64"\n        "
	                "r42770257:%"PRIu64"/%"PRIu64" "
	                "r42783724:%"PRIu64"/%"PRIu64" "
	                "r42784847:%"PRIu64"/%"PRIu64" "
	                "r42946744:%"PRIu64"/%"PRIu64"\n",
	                st.el_aupclobbers,
	                st.el_aueunknowns,
	                st.el_failedsyscalls,
	                st.el_missingtoken,
	                st.el_ooms,
	                st.el_radar38845422_fatal,
	                st.el_radar38845422,
	                st.el_radar38845784,
	                st.el_radar39267328_fatal,
	                st.el_radar39267328,
	                st.el_radar39623812_fatal,
	                st.el_radar39623812,
	                st.el_radar42770257_fatal,
	                st.el_radar42770257,
	                st.el_radar42783724_fatal,
	                st.el_radar42783724,
	                st.el_radar42784847_fatal,
	                st.el_radar42784847,
	                st.el_radar42946744_fatal,
	                st.el_radar42946744);

	fprintf(stderr, "procmon "
	                "actprc:%"PRIu32" "
	                "actimg:%"PRIu32" "
	                "liveacq:%"PRIu64" "
	                "miss bp:%"PRIu64" "
	                "fs:%"PRIu64" "
	                "es:%"PRIu64" "
	                "ei:%"PRIu64" "
	                "cs:%"PRIu64" "
	                "gc:%"PRIu64" "
	                "oom:%"PRIu64"\n",
	                st.pm.procs,
	                st.pm.images,
	                st.pm.liveacq,
	                st.pm.miss_bypid,
	                st.pm.miss_forksubj,
	                st.pm.miss_execsubj,
	                st.pm.miss_execinterp,
	                st.pm.miss_chdirsubj,
	                st.pm.miss_getcwd,
	                st.pm.ooms);

	fprintf(stderr, "hackmon "
	                "recvd:%"PRIu64" "
	                "procd:%"PRIu64" "
	                "oom:%"PRIu64"\n",
	                st.hm.recvd,
	                st.hm.procd,
	                st.hm.ooms);

	fprintf(stderr, "filemon "
	                "recvd:%"PRIu64" "
	                "procd:%"PRIu64" "
	                "lpmiss:%"PRIu64" "
	                "oom:%"PRIu64"\n",
	                st.fm.recvd,
	                st.fm.procd,
	                st.fm.lpmiss,
	                st.fm.ooms);

	fprintf(stderr, "sockmon "
	                "recvd:%"PRIu64" "
	                "procd:%"PRIu64" "
	                "oom:%"PRIu64"\n",
	                st.sm.recvd,
	                st.sm.procd,
	                st.sm.ooms);

	if (kefd != -1) {
		fprintf(stderr, "kext cdevq "
		                "buckets:%"PRIu32"/~ "
		                "visitors:%"PRIu32" "
		                "timeout:%"PRIu64" "
		                "err:%"PRIu64" "
		                "defer:%"PRIu64" "
		                "deny:%"PRIu64"\n",
		                st.ke.cdev_qsize,
		                st.ke.kauth_visitors,
		                st.ke.kauth_timeouts,
		                st.ke.kauth_errors,
		                st.ke.kauth_defers,
		                st.ke.kauth_denies);

		fprintf(stderr, "prep queue "
		                "buckets:%"PRIu64"/~ "
		                "lookup:%"PRIu64" "
		                "miss:%"PRIu64" "       /* normal at startup */
		                "drop:%"PRIu64" "       /* too many ooo */
		                "bktskip:%"PRIu64"\n",  /* ooo arrival search */
		                st.pm.pqsize,
		                st.pm.pqlookup,
		                st.pm.pqmiss,
		                st.pm.pqdrop,
		                st.pm.pqskip);
	}

	fprintf(stderr, "aupi cdevq "
	                "buckets:%u/%u "
	                "insert:%u "
	                "read:%u "
	                "drop:%u\n",
	                st.ap.qlen,
	                st.ap.qlimit,
	                st.ap.inserts,
	                st.ap.reads,
	                st.ap.drops);

	fprintf(stderr, "work queue "
	                "buckets:%"PRIu32"/~\n",
	                st.wq.qsize);

	fprintf(stderr, "log  queue "
	                "buckets:%"PRIu32"/~ "
	                "[0]:%"PRIu64" "
	                "[1]:%"PRIu64" "
	                "[2]:%"PRIu64" "
	                "[3]:%"PRIu64" "
	                "[4]:%"PRIu64" "
	                "[5]:%"PRIu64" "
	                "[6]:%"PRIu64" "
	                "[7]:%"PRIu64" "
	                "err:%"PRIu64"\n",
	                st.lq.qsize,
	                st.lq.counts[LOGEVT_XNUMON_OPS],
	                st.lq.counts[LOGEVT_XNUMON_STATS],
	                st.lq.counts[LOGEVT_IMAGE_EXEC],
	                st.lq.counts[LOGEVT_PROCESS_ACCESS],
	                st.lq.counts[LOGEVT_LAUNCHD_ADD],
	                st.lq.counts[LOGEVT_SOCKET_LISTEN],
	                st.lq.counts[LOGEVT_SOCKET_ACCEPT],
	                st.lq.counts[LOGEVT_SOCKET_CONNECT],
	                st.lq.errors);
	_Static_assert(LOGEVT_SIZE == 8, "number of handled event types here");

	fprintf(stderr, "hash cache "
	                "buckets:%"PRIu32"/%"PRIu32" "
	                "put:%"PRIu64" "
	                "get:%"PRIu64" "
	                "hit:%"PRIu64" "
	                "miss:%"PRIu64" "       /* once per binary inode */
	                "inv:%"PRIu64"\n",      /* modified binary inodes */
	                st.ch.used, st.ch.size,
	                st.ch.puts, st.ch.gets,
	                st.ch.hits, st.ch.misses,
	                st.ch.invalids);

	fprintf(stderr, "csig cache "
	                "buckets:%"PRIu32"/%"PRIu32" "
	                "put:%"PRIu64" "
	                "get:%"PRIu64" "
	                "hit:%"PRIu64" "
	                "miss:%"PRIu64" "       /* once per binary content */
	                "inv:%"PRIu64"\n",      /* cannot happen */
	                st.cc.used, st.cc.size,
	                st.cc.puts, st.cc.gets,
	                st.cc.hits, st.cc.misses,
	                st.cc.invalids);

	fprintf(stderr, "ldpl cache "
	                "buckets:%"PRIu32"/%"PRIu32" "
	                "put:%"PRIu64" "
	                "get:%"PRIu64" "
	                "hit:%"PRIu64" "
	                "miss:%"PRIu64" "       /* once per launchd plist */
	                "inv:%"PRIu64"\n",      /* modified launchd plist */
	                st.cl.used, st.cl.size,
	                st.cl.puts, st.cl.gets,
	                st.cl.hits, st.cl.misses,
	                st.cl.invalids);

	return 0;
}

/*
 * Handles SIGHUP.
 */
static int
sighup_arrived(UNUSED int sig, UNUSED void *udata) {
	if (log_reinit() == -1) {
		fprintf(stderr, "Failed to reopen the log\n");
		return -1;
	}
	return 0;
}

/*
 * Called by stats timer, configurable interval.
 */
static int
stats_timer_fired(UNUSED int ident, UNUSED void *udata) {
	if ((log_event_xnumon_stats() == -1) && (errno == ENOMEM))
		ooms++;
	return 0;
}

/*
 * Called by audit policy watchdog timer, every five minutes.
 */
int aupol_wanted = -1;
static int
aupol_timer_fired(UNUSED int ident, UNUSED void *udata) {
	assert(aupol_wanted != -1);
	switch (aupolicy_ensure(aupol_wanted)) {
	case 0:
		return 0;
	case 1:
		aupclobbers++;
		return 0;
	default:
		fprintf(stderr, "Failed to configure audit policy\n");
		return -1;
	}
	/* not reached */
}

static stat_attr_t cfgattr[2];

/*
 * Called by config timer, every five minutes.
 */
static int
config_timer_fired(UNUSED int ident, void *udata) {
	config_t *cfg = (config_t *)udata;
	if (sys_pathattr(&cfgattr[1], cfg->path) == -1) {
		fprintf(stderr, "Configuration file disappeared, "
		                "exiting to reload config\n");
		running = false;
		return -1;
	}
	if ((cfgattr[0].ino != 0)
	 && ((cfgattr[0].dev != cfgattr[1].dev)
	  || (cfgattr[0].ino != cfgattr[1].ino)
	  || (!timespec_equal(&cfgattr[0].mtime, &cfgattr[1].mtime))
	  || (!timespec_equal(&cfgattr[0].ctime, &cfgattr[1].ctime))
	  || (!timespec_equal(&cfgattr[0].btime, &cfgattr[1].btime)))) {
		fprintf(stderr, "Configuration change detected, "
		                "exiting to reload config\n");
		running = false;
		return -1;
	}
	cfgattr[0] = cfgattr[1];
	return 0;
}

/*
 * Capture the initial reference stat of the config file.
 *
 * Will be called before any other initialization, so cannot use code that
 * requires initialization.
 */
static void
config_timer_init(config_t *cfg, int ident) {
	bzero(cfgattr, 2*sizeof(stat_attr_t));
	(void)config_timer_fired(ident, cfg);
}

/*
 * Handles SIGUSR1.
 */
static int
sigusr1_arrived(UNUSED int sig, UNUSED void *udata) {
	if ((log_event_xnumon_stats() == -1) && (errno == ENOMEM))
		ooms++;
	return 0;
}

#define TIMER_AUPOL     1
#define TIMER_STATS     2
#define TIMER_CONFIG    3

int
evtloop_run(config_t *cfg) {
	kevent_ctx_t sigquit_ctx = KEVENT_CTX_SIGNAL(sigquit_arrived, cfg);
	kevent_ctx_t sigtstp_ctx = KEVENT_CTX_SIGNAL(sigtstp_arrived, cfg);
	kevent_ctx_t siginfo_ctx = KEVENT_CTX_SIGNAL(siginfo_arrived, cfg);
	kevent_ctx_t sighup_ctx  = KEVENT_CTX_SIGNAL(sighup_arrived, cfg);
	kevent_ctx_t sigusr1_ctx = KEVENT_CTX_SIGNAL(sigusr1_arrived, cfg);
	kevent_ctx_t auef_ctx    = KEVENT_CTX_FD_READ(auef_readable, cfg);
	kevent_ctx_t kefd_ctx    = KEVENT_CTX_FD_READ(kefd_readable, cfg);
	kevent_ctx_t aptm_ctx    = KEVENT_CTX_TIMER(aupol_timer_fired, cfg);
	kevent_ctx_t sttm_ctx    = KEVENT_CTX_TIMER(stats_timer_fired, cfg);
	kevent_ctx_t cftm_ctx    = KEVENT_CTX_TIMER(config_timer_fired, cfg);
	kqueue_t *kq = NULL;
	int pidc;
	pid_t *pidv;
	int rv;

	auef = NULL;
	aupclobbers = 0;
	aueunknowns = 0;
	failedsyscalls = 0;
	radar38845422_fatal = 0;
	radar38845422 = 0;
	radar38845784 = 0;
	radar39267328_fatal = 0;
	radar39267328 = 0;
	radar39623812_fatal = 0;
	radar39623812 = 0;
	radar42770257_fatal = 0;
	radar42783724 = 0;
	radar42783724_fatal = 0;
	radar42784847 = 0;
	radar42784847_fatal = 0;
	radar42946744_fatal = 0;
	missingtoken = 0;
	ooms = 0;
	xnumon_pid = getpid();

	/* system-global audit(4) setup: audit policy */
	aupol_wanted = AUDIT_ARGV;
	if (cfg->envlevel > 0)
		aupol_wanted |= AUDIT_ARGE;
	if (aupol_timer_fired(TIMER_AUPOL, NULL) == -1)
		goto errout;

	/* system-global audit(4) setup: audit class */
	if (auclass_addmask(AC_XNUMON, auclass_xnumon_events_procmon) == -1) {
		fprintf(stderr, "Failed to configure AC_XNUMON class mask\n");
		goto errout;
	}
	if (LOGEVT_WANT(cfg->events, LOGEVT_HACKMON) &&
	    auclass_addmask(AC_XNUMON, auclass_xnumon_events_hackmon) == -1) {
		fprintf(stderr, "Failed to configure AC_XNUMON class mask\n");
		goto errout;
	}
	if (LOGEVT_WANT(cfg->events, LOGEVT_FILEMON) &&
	    auclass_addmask(AC_XNUMON, auclass_xnumon_events_filemon) == -1) {
		fprintf(stderr, "Failed to configure AC_XNUMON class mask\n");
		goto errout;
	}
	if (LOGEVT_WANT(cfg->events, LOGEVT_SOCKMON) &&
	    auclass_addmask(AC_XNUMON, auclass_xnumon_events_sockmon) == -1) {
		fprintf(stderr, "Failed to configure AC_XNUMON class mask\n");
		goto errout;
	}

	/* load kext */
	if ((cfg->kextlevel > 0) && (kextctl_load() == -1)) {
		fprintf(stderr, "Failed to load kernel extension\n");
	}

	/* initialize */
	if (cfg->launchd_mode) {
		config_timer_init(cfg, TIMER_CONFIG);
	}
	cachehash_init();
	cachecsig_init();
	cacheldpl_init();
	if (auevent_init() == -1) {
		fprintf(stderr, "Failed to initialize auevent\n");
		rv = -1;
		goto errout_silent;
	}
	if (os_init() == -1) {
		fprintf(stderr, "Failed to initialize os version\n");
		rv = -1;
		goto errout_silent;
	}
	if (codesign_init(cfg) == -1) {
		fprintf(stderr, "Failed to initialize codesign\n");
		rv = -1;
		goto errout_silent;
	}
	if (log_init(cfg) == -1) {
		fprintf(stderr, "Failed to initialize logging\n");
		rv = -1;
		goto errout_silent;
	}
	if (work_init(cfg) == -1) {
		fprintf(stderr, "Failed to initialize work queue\n");
		rv = -1;
		goto errout_silent;
	}
	if (procmon_init(cfg) == -1) {
		fprintf(stderr, "Failed to initialize procmon\n");
		rv = -1;
		goto errout_silent;
	}
	if (filemon_init(cfg) == -1) {
		fprintf(stderr, "Failed to initialize filemon\n");
		rv = -1;
		goto errout_silent;
	}
	hackmon_init(cfg);
	sockmon_init(cfg);

	/* try to spawn kextloop thread */
	if (cfg->kextlevel > 0 && kextloop_spawn(&kefd_ctx) == -1) {
		cfg->kextlevel = 0;
		fprintf(stderr, "Proceeding without kext\n");
	}

	/* open kqueue */
	kq = kqueue_new();
	if (!kq) {
		fprintf(stderr, "kqueue_new() failed: %s (%i)\n",
		                strerror(errno), errno);
		rv = -1;
		goto errout_silent;
	}

	/* install kevent-based signal handlers */
	rv = kqueue_add_signal(kq, SIGQUIT, &sigquit_ctx);
	if (rv == -1) {
		fprintf(stderr, "kqueue_add_signal(SIGQUIT) failed: %s (%i)\n",
		                strerror(errno), errno);
		rv = -1;
		goto errout_silent;
	}
	rv = kqueue_add_signal(kq, SIGTERM, &sigquit_ctx);
	if (rv == -1) {
		fprintf(stderr, "kqueue_add_signal(SIGTERM) failed: %s (%i)\n",
		                strerror(errno), errno);
		rv = -1;
		goto errout_silent;
	}
	rv = kqueue_add_signal(kq, SIGINT, &sigquit_ctx);
	if (rv == -1) {
		fprintf(stderr, "kqueue_add_signal(SIGINT) failed: %s (%i)\n",
		                strerror(errno), errno);
		rv = -1;
		goto errout_silent;
	}
	rv = kqueue_add_signal(kq, SIGINFO, &siginfo_ctx);
	if (rv == -1) {
		fprintf(stderr, "kqueue_add_signal(SIGINFO) failed: %s (%i)\n",
		                strerror(errno), errno);
		rv = -1;
		goto errout_silent;
	}
	rv = kqueue_add_signal(kq, SIGHUP, &sighup_ctx);
	if (rv == -1) {
		fprintf(stderr, "kqueue_add_signal(SIGHUP) failed: %s (%i)\n",
		                strerror(errno), errno);
		rv = -1;
		goto errout_silent;
	}
	rv = kqueue_add_signal(kq, SIGUSR1, &sigusr1_ctx);
	if (rv == -1) {
		fprintf(stderr, "kqueue_add_signal(SIGUSR1) failed: %s (%i)\n",
		                strerror(errno), errno);
		rv = -1;
		goto errout_silent;
	}
	if (cfg->kextlevel > 0) {
		rv = kqueue_add_signal(kq, SIGTSTP, &sigtstp_ctx);
		if (rv == -1) {
			fprintf(stderr, "kqueue_add_signal(SIGTSTP) "
			                "failed: %s (%i)\n",
			                strerror(errno), errno);
			rv = -1;
			goto errout_silent;
		}
	}

	/* open auditpipe to start queueing audit events */
	if ((auef = aupipe_fopen(AC_XNUMON)) == NULL) {
		fprintf(stderr, "aupipe_fopen(AC_XNUMON) failed\n");
		rv = -1;
		goto errout_silent;
	}

	/* walk already running processes */
	pidv = sys_pidlist(&pidc);
	if (!pidv) {
		fprintf(stderr, "sys_pidlist() failed\n");
		rv = -1;
		goto errout_silent;
	}
	fprintf(stderr, "Preloading pid");
	for (int i = pidc - 1; i >= 0; i--) {
		fprintf(stderr, " %i", pidv[i]);
		procmon_preloadpid(pidv[i]);
	}
	free(pidv);
	fprintf(stderr, "\n");

	/* log xnumon start */
	if (log_event_xnumon_start() == -1) {
		fprintf(stderr, "log_event_xnumon_start() failed\n");
		rv = -1;
		goto errout_silent;
	}

	/* add auditpipe to kqueue */
	rv = kqueue_add_fd_read(kq, fileno(auef), &auef_ctx);
	if (rv == -1) {
		fprintf(stderr, "kqueue_add_fd_read(/dev/auditpipe) failed: "
		                "%s (%i)\n", strerror(errno), errno);
		rv = -1;
		goto errout;
	}

	/* start audit(4) policy watchdog timer */
	rv = kqueue_add_timer(kq, TIMER_AUPOL, 300, &aptm_ctx);
	if (rv == -1) {
		fprintf(stderr, "kqueue_add_timer(TIMER_AUPOL) failed: "
		                "%s (%i)\n", strerror(errno), errno);
		rv = -1;
		goto errout;
	}

	/* start stats timer */
	rv = kqueue_add_timer(kq, TIMER_STATS, cfg->stats_interval, &sttm_ctx);
	if (rv == -1) {
		fprintf(stderr, "kqueue_add_timer(TIMER_STATS) failed: "
		                "%s (%i)\n", strerror(errno), errno);
		rv = -1;
		goto errout;
	}

	if (cfg->launchd_mode) {
		/* start config file timer */
		rv = kqueue_add_timer(kq, TIMER_CONFIG, 300, &cftm_ctx);
		if (rv == -1) {
			fprintf(stderr, "kqueue_add_timer(TIMER_CONFIG) failed"
			                ": %s (%i)\n", strerror(errno), errno);
			rv = -1;
			goto errout;
		}
	}

	/* event dispatch loop */
	DEBUG(cfg->debug, "xnumon_start", "init complete");
	running = true;
	for (;;) {
		rv = kqueue_dispatch(kq);
		if (!running)
			break;
		if (rv != 0) {
			fprintf(stderr, "kevent_dispatch() failed\n");
			rv = -1;
			goto errout;
		}
	}

	/* stop and join the kextloop thread */
	if (cfg->kextlevel > 0) {
		kextloop_break();
	}

	rv = 0;
errout:
	/* log xnumon stats and stop */
	DEBUG(cfg->debug, "xnumon_stop", "shutting down");
	(void)log_event_xnumon_stats();
	if (log_event_xnumon_stop() == -1) {
		fprintf(stderr, "log_event_xnumon_stop() failed\n");
		rv = -1;
		goto errout;
	}

errout_silent:
	/* system-global audit(4) cleanup */
	if (auclass_removemask(AC_XNUMON,
	                       auclass_xnumon_events_procmon) == -1 ||
	    auclass_removemask(AC_XNUMON,
	                       auclass_xnumon_events_hackmon) == -1 ||
	    auclass_removemask(AC_XNUMON,
	                       auclass_xnumon_events_filemon) == -1) {
		fprintf(stderr, "Failed to configure AC_XNUMON class mask\n");
	}

	if (kq)
		kqueue_free(kq);
	if (auef) {
		fclose(auef);
		auef = NULL;
	}
	work_fini();            /* drain work queue */
	sockmon_fini();
	hackmon_fini();
	filemon_fini();
	procmon_fini();         /* clear kext queue */
	log_fini();             /* drain log queue */
	assert(procmon_images() == 0);
	codesign_fini();
	os_fini();
	cacheldpl_fini();
	cachecsig_fini();
	cachehash_fini();
	return rv;
}

