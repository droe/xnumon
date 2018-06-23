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
#include "procmon.h"
#include "filemon.h"
#include "hackmon.h"
#include "sys.h"
#include "str.h"
#include "time.h"
#include "os.h"
#include "attrib.h"

#include <stdint.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>

static bool running = true;
static int kefd = -1;
static FILE *auef = NULL;
static pid_t xnumon_pid;
static uint64_t aueunknowns = 0;
static uint64_t failedsyscalls = 0;
static uint64_t radar38845422 = 0;
static uint64_t radar39267328 = 0;
static uint64_t radar39623812 = 0;
static uint64_t needpath = 0; /* unknown missing path bug */
static uint64_t needargv = 0; /* need argv to recover from path bug */
static uint64_t needcwd = 0;  /* need cwd to recover from path bug */
static uint64_t ooms = 0;

/* return 1 if kextctl should be treated with priority */
static bool
kextctl_priority(UNUSED int fd, UNUSED void *udata) {
	return procmon_kpriority();
}

static int
kextctl_readable(int fd, UNUSED void *udata) {
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

/*
 * Called when the auditpipe file descriptor is readable.
 *
 * XNU BSD syscalls:
 * https://github.com/apple/darwin-xnu/blob/master/bsd/kern/syscalls.master
 * XNU Mach syscalls:
 * https://github.com/apple/darwin-xnu/blob/master/osfmk/mach/syscall_sw.h
 *
 * This function contains workarounds for the following bugs in audit(4):
 * 38845422: audit(4): nonsensical path and missing attr for posix_spawn(2)
 * 38845784: audit(4): spurious return value for execve(2)
 * 39267328: audit(4): target path not resolved for rename(2)
 * 39623812: audit(4): path not resolved for utimes(2)
 */
static int
auef_readable(UNUSED int fd, UNUSED void *udata) {
	audit_event_t ev;
	const char *cwd;
	char *path;
	int rv;

	auevent_init(&ev);
	rv = auevent_fread(&ev, NULL, auef);
	if (rv == -1 || rv == 0) {
		if (ev.flags & AEFLAG_ENOMEM)
			ooms++;
		auevent_destroy(&ev);
		return rv;
	}

#ifdef DEBUG_AUDITPIPE
	auevent_fprint(stderr, &ev);
#endif

	switch (ev.type) {

	/*
	 * Events for process monitoring.
	 */

	case AUE_FORK:
	case AUE_VFORK:
		assert(ev.return_present);
		if (ev.return_value > INT_MAX) {
			failedsyscalls++;
			break;
		}
		assert(ev.subject_present);
		procmon_fork(&ev.tv, &ev.subject, ev.return_value);
		break;

	case AUE_POSIX_SPAWN:
		assert(ev.return_present);
		if (ev.return_value) {
			/* posix_spawnp spams an event for each directory in
			 * $PATH with return_value==2 until it finds the actual
			 * matching executable (10.11.6) */
			failedsyscalls++;
			break;
		}
		assert(ev.subject_present);
		/*
		 * On at least 10.11.6 and 10.12.6, the following happens:
		 * path is /dev/console when launchd spawns xpcproxy,
		 * path is /dev/null when xpcproxy execs the XPC target,
		 * path is $CWD/dev/ttysNNN when lldb spawns debug subject;
		 * in all of these cases, no attr token is provided, and there
		 * is only one path instead of two.
		 *
		 * Reported to Apple as bug 38845422 on 2018-03-25.
		 *
		 * As a result, whenever no attr is present or path starts in
		 * /dev, assume a buggy path.  First try the path by pid.
		 * If that fails, employ less reliable ways to work around the
		 * issue.
		 */
		path = (char *)(ev.path[1] ? ev.path[1] : ev.path[0]);
		if (!ev.attr_present || !path ||
		    !str_beginswith(path, "/dev/")) {
			radar38845422++;
			path = sys_pidpath(ev.args[0].present ?
			                   ev.args[0].value : ev.subject.pid);
			if (!path) {
				if (!ev.execarg) {
					needargv++;
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
			             ev.attr_present ? &ev.attr : NULL,
			             ev.execarg);
			ev.execarg = NULL; /* pass ownership to procmon */
			break;
		}
		assert(ev.args[0].present);
		procmon_spawn(&ev.tv,
		              &ev.subject,
		              ev.args[0].value,
		              path,
		              ev.attr_present ? &ev.attr : NULL,
		              ev.execarg);
		ev.execarg = NULL; /* pass ownership to procmon */
		break;

	case AUE_EXEC:
	case AUE_EXECVE:
	case AUE_MAC_EXECVE:
		/*
		 * On at least 10.11.6, audit records for successful execve
		 * invocations sometimes have a pid as return value, for
		 * example when being spawned from make, which does not
		 * indicate failure; only treat negative values as errors.
		 *
		 * Reported to Apple as bug 38845784 on 2018-03-25.
		 */
		if (ev.return_present && ev.return_value > INT_MAX) {
			failedsyscalls++;
			break;
		}
		assert(ev.subject_present);
		if (!ev.path[0]) {
			needpath++;
			break;
		}
		path = (char *)(ev.path[1] ? ev.path[1] : ev.path[0]);
		assert(path);
		path = strdup(path);
		if (!path) {
			ooms++;
			break;
		}
		procmon_exec(&ev.tv,
		             &ev.subject,
		             path,
		             ev.attr_present ? &ev.attr : NULL,
		             ev.execarg);
		ev.execarg = NULL; /* pass ownership to procmon */
		break;

	case AUE_EXIT:
		/* exit never fails; audit event not triggered if process got
		 * terminated in other ways than calling exit() */
		assert(ev.subject_present);
		procmon_exit(ev.subject.pid);
		break;

	case AUE_WAIT4:
		assert(ev.return_present);
		if (ev.return_value == 0 || ev.return_value > INT_MAX) {
			failedsyscalls++;
			break;
		}
		/* cannot distinguish terminated and stopped processes */
		procmon_wait4(ev.return_value);
		break;

	case AUE_CHDIR:
	case AUE_FCHDIR:
		assert(ev.return_present);
		if (ev.return_value) {
			failedsyscalls++;
			break;
		}
		assert(ev.subject_present);
		if (!ev.path[0]) {
			needpath++;
			break;
		}
		path = (char *)(ev.path[1] ? ev.path[1] : ev.path[0]);
		assert(path);
		path = strdup(path);
		if (!path) {
			ooms++;
			break;
		}
		procmon_chdir(ev.subject.pid, path);
		break;

	/*
	 * Events for tracking inter-process access commonly used for
	 * code injection and other manipulation.
	 */

	case AUE_TASKFORPID:
		assert(ev.return_present);
		if (ev.return_value) {
			failedsyscalls++;
			break;
		}
		assert(ev.subject_present);
		/* The PROCESS_PID_TOKENS macro in XNU creates a process token
		 * from pid arg 2 only if pid > 0. */
		assert(ev.process_present || ev.args[2].present);
		hackmon_taskforpid(&ev.tv, &ev.subject,
		                   ev.process_present ? &ev.process : NULL,
		                   ev.args[2].present ? ev.args[2].value : -1);
		break;

	case AUE_PTRACE:
		assert(ev.return_present);
		if (ev.return_value) {
			failedsyscalls++;
			break;
		}
		assert(ev.subject_present);
		/* The PROCESS_PID_TOKENS macro in XNU creates a process token
		 * from pid arg 2 only if pid > 0. */
		assert(ev.process_present || ev.args[2].present);
		hackmon_ptrace(&ev.tv, &ev.subject,
		               ev.process_present ? &ev.process : NULL,
		               ev.args[2].present ? ev.args[2].value : -1);
		break;

	/*
	 * Events for tracking file modifications.
	 */

	case AUE_CLOSE:
		assert(ev.return_present);
		if (ev.return_value) {
			failedsyscalls++;
			break;
		}
		if (!ev.path[0]) {
			/* closed file descriptor does not point to vnode */
			break;
		}
		assert(ev.subject_present);
		/* avoid reacting on our own close invocations */
		if (ev.subject.pid == xnumon_pid)
			break;
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
		assert(ev.return_present);
		if (ev.return_value) {
			failedsyscalls++;
			break;
		}
		assert(ev.subject_present);
		/*
		 * On at least 10.11.6, records include only an unresolved
		 * path.
		 *
		 * Reported to Apple as bug 39623812 on 2018-04-21.
		 */
		if (ev.path[1]) {
			/* two path tokens */
			path = strdup(ev.path[1]);
			if (!path)
				ooms++;
		} else if (ev.path[0]) {
			/* one path token, assume unresolved if no attr */
			if (ev.attr_present) {
				path = strdup(ev.path[0]);
				if (!path)
					ooms++;
			} else {
				radar39623812++;
				cwd = procmon_getcwd(ev.subject.pid);
				if (!cwd && (errno == ENOMEM))
					ooms++;
				path = sys_realpath(ev.path[0], cwd);
				if (!path) {
					if (errno == ENOMEM)
						ooms++;
					else
						needcwd++;
				}
			}
		} else {
			path = NULL;
			needpath++;
		}
		if (!path)
			/* counted above */
			break;
		filemon_touched(&ev.tv, &ev.subject, path);
		break;

	case AUE_RENAME:
	case AUE_RENAMEAT:
		assert(ev.return_present);
		if (ev.return_value) {
			failedsyscalls++;
			break;
		}
		assert(ev.subject_present);
		/*
		 * On at least 10.11.6, records include only an unresolved
		 * target path.
		 *
		 * Reported to Apple as bug 39267328 on 2018-04-08.
		 */
		if (ev.path[1] && !ev.path[2]) {
			/* two path tokens, assume both resolved */
			path = strdup(ev.path[1]);
			if (!path)
				ooms++;
		} else if (ev.path[3]) {
			/* four path tokens, as expected */
			path = strdup(ev.path[3]);
			if (!path)
				ooms++;
		} else if (ev.path[2] && !ev.path[3]) {
			/* three path tokens, assume third unresolved dpath */
			radar39267328++;
			cwd = procmon_getcwd(ev.subject.pid);
			if (!cwd && (errno == ENOMEM))
				ooms++;
			path = sys_realpath(ev.path[2], cwd);
			if (!path) {
				if (errno == ENOMEM)
					ooms++;
				else
					needcwd++;
			}
		} else {
			path = NULL;
			needpath++;
		}
		if (!path)
			/* counted above */
			break;
		filemon_touched(&ev.tv, &ev.subject, path);
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

	auevent_destroy(&ev); /* free all allocated members not NULLed above */
	return 0;
}

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
	st->el_aueunknowns = aueunknowns;
	st->el_failedsyscalls = failedsyscalls;
	st->el_radar38845422 = radar38845422;
	st->el_radar39623812 = radar39623812;
	st->el_radar39267328 = radar39267328;
	st->el_needpath = needpath;
	st->el_needargv = needargv;
	st->el_needcwd  = needcwd;
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
	                "aueunknown:%"PRIu64" "
	                "failedsyscalls:%"PRIu64"\n        "
	                "radar38845422:%"PRIu64" "
	                "radar39267328:%"PRIu64" "
	                "radar39623812:%"PRIu64"\n        "
	                "needpath:%"PRIu64" "
	                "needargv:%"PRIu64" "
	                "needcwd:%"PRIu64" "
	                "oom:%"PRIu64"\n",
	                st.el_aueunknowns,
	                st.el_failedsyscalls,
	                st.el_radar38845422,
	                st.el_radar39267328,
	                st.el_radar39623812,
	                st.el_needpath,
	                st.el_needargv,
	                st.el_needcwd,
	                st.el_ooms);

	fprintf(stderr, "procmon "
	                "actprocs:%"PRIu32" "
	                "actimages:%"PRIu32" "
	                "miss bp:%"PRIu64" "
	                "fs:%"PRIu64" "
	                "es:%"PRIu64" "
	                "ei:%"PRIu64" "
	                "cs:%"PRIu64" "
	                "gc:%"PRIu64" "
	                "oom:%"PRIu64"\n",
	                st.pm.procs,
	                st.pm.images,
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
	                st.hm.receiveds,
	                st.hm.processeds,
	                st.hm.ooms);

	fprintf(stderr, "filemon "
	                "recvd:%"PRIu64" "
	                "procd:%"PRIu64" "
	                "lpmiss:%"PRIu64" "
	                "oom:%"PRIu64"\n",
	                st.fm.receiveds,
	                st.fm.processeds,
	                st.fm.lpmiss,
	                st.fm.ooms);

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
		                st.pm.kqsize,
		                st.pm.kqlookups,
		                st.pm.kqnotfounds,
		                st.pm.kqtimeouts,
		                st.pm.kqskips);
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
	                "[1]:%"PRIu64" "
	                "[2]:%"PRIu64" "
	                "[3]:%"PRIu64" "
	                "[4]:%"PRIu64" "
	                "[5]:%"PRIu64" "
	                "err:%"PRIu64"\n",
	                st.lq.qsize,
	                st.lq.counts[LOGEVT_XNUMON_OPS],
	                st.lq.counts[LOGEVT_XNUMON_STATS],
	                st.lq.counts[LOGEVT_IMAGE_EXEC],
	                st.lq.counts[LOGEVT_PROCESS_ACCESS],
	                st.lq.counts[LOGEVT_LAUNCHD_ADD],
	                st.lq.errors);
	_Static_assert(LOGEVT_SIZE == 5, "number of handled event types here");

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
 * Called by stats timer, every hour.
 */
static int
stats_timer_fired(UNUSED int ident, UNUSED void *udata) {
	if ((log_event_xnumon_stats() == -1) && (errno == ENOMEM))
		ooms++;
	return 0;
}

static stat_attr_t cfgattr[2];

/*
 * Called by config timer, every five minutes.
 */
static int
config_timer_fired(UNUSED int ident, void *udata) {
	config_t *cfg = (config_t *)udata;
	fprintf(stderr, "config_timer_fired\n");
	if (sys_pathattr(&cfgattr[1], cfg->path) == -1) {
		fprintf(stderr, "Configuration file disappeared, exiting\n");
		sleep(5); /* give deployment some time to finish deploying */
		running = false;
		return -1;
	}
	if ((cfgattr[0].ino != 0)
	 && ((cfgattr[0].dev != cfgattr[1].dev)
	  || (cfgattr[0].ino != cfgattr[1].ino)
	  || (!timespec_equal(&cfgattr[0].mtime, &cfgattr[1].mtime))
	  || (!timespec_equal(&cfgattr[0].ctime, &cfgattr[1].ctime))
	  || (!timespec_equal(&cfgattr[0].btime, &cfgattr[1].btime)))) {
		fprintf(stderr, "Configuration change detected, exiting\n");
		running = false;
		return -1;
	}
	cfgattr[0] = cfgattr[1];
	return 0;
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

int
evtloop_run(config_t *cfg) {
	kevent_ctx_t sigquit_ctx = KEVENT_CTX_SIGNAL(sigquit_arrived, NULL);
	kevent_ctx_t sigtstp_ctx = KEVENT_CTX_SIGNAL(sigtstp_arrived, NULL);
	kevent_ctx_t siginfo_ctx = KEVENT_CTX_SIGNAL(siginfo_arrived, NULL);
	kevent_ctx_t sighup_ctx  = KEVENT_CTX_SIGNAL(sighup_arrived, NULL);
	kevent_ctx_t sigusr1_ctx = KEVENT_CTX_SIGNAL(sigusr1_arrived, NULL);
	kevent_ctx_t kefd_ctx    = KEVENT_CTX_FD_READ_PRIO(kextctl_readable,
	                                                   kextctl_priority,
	                                                   NULL);
	kevent_ctx_t auef_ctx    = KEVENT_CTX_FD_READ(auef_readable, NULL);
	kevent_ctx_t sttm_ctx    = KEVENT_CTX_TIMER(stats_timer_fired, NULL);
	kevent_ctx_t cftm_ctx    = KEVENT_CTX_TIMER(config_timer_fired, cfg);
	int pidc;
	pid_t *pidv;
	int rv;

	kefd = -1;
	auef = NULL;
	aueunknowns = 0;
	failedsyscalls = 0;
	radar38845422 = 0;
	radar39267328 = 0;
	radar39623812 = 0;
	needpath = 0;
	needargv = 0;
	needcwd = 0;
	ooms = 0;
	xnumon_pid = getpid();

	if ((cfg->kextlevel > 0) && (kextctl_load() == -1)) {
		fprintf(stderr, "Failed to load kernel extension\n");
	}

	/* initialize */
	cachehash_init();
	cachecsig_init();
	cacheldpl_init();
	if (os_init() == -1) {
		fprintf(stderr, "Failed to initialize os version\n");
		rv = -1;
		goto errout_silent;
	}
	if (log_init(cfg) == -1) {
		fprintf(stderr, "Failed to initialize logging\n");
		rv = -1;
		goto errout_silent;
	}
	if (work_init() == -1) {
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

	/* open kqueue */
	if (kqueue_init() == -1) {
		fprintf(stderr, "kqueue_init() failed: %s (%i)\n",
		                strerror(errno), errno);
		rv = -1;
		goto errout_silent;
	}

	/* install kevent-based signal handlers */
	rv = kqueue_add_signal(SIGQUIT, &sigquit_ctx);
	if (rv == -1) {
		fprintf(stderr, "kqueue_add_signal(SIGQUIT) failed: %s (%i)\n",
		                strerror(errno), errno);
		rv = -1;
		goto errout_silent;
	}
	rv = kqueue_add_signal(SIGTERM, &sigquit_ctx);
	if (rv == -1) {
		fprintf(stderr, "kqueue_add_signal(SIGTERM) failed: %s (%i)\n",
		                strerror(errno), errno);
		rv = -1;
		goto errout_silent;
	}
	rv = kqueue_add_signal(SIGINT, &sigquit_ctx);
	if (rv == -1) {
		fprintf(stderr, "kqueue_add_signal(SIGINT) failed: %s (%i)\n",
		                strerror(errno), errno);
		rv = -1;
		goto errout_silent;
	}
	rv = kqueue_add_signal(SIGINFO, &siginfo_ctx);
	if (rv == -1) {
		fprintf(stderr, "kqueue_add_signal(SIGINFO) failed: %s (%i)\n",
		                strerror(errno), errno);
		rv = -1;
		goto errout_silent;
	}
	rv = kqueue_add_signal(SIGHUP, &sighup_ctx);
	if (rv == -1) {
		fprintf(stderr, "kqueue_add_signal(SIGHUP) failed: %s (%i)\n",
		                strerror(errno), errno);
		rv = -1;
		goto errout_silent;
	}
	rv = kqueue_add_signal(SIGUSR1, &sigusr1_ctx);
	if (rv == -1) {
		fprintf(stderr, "kqueue_add_signal(SIGUSR1) failed: %s (%i)\n",
		                strerror(errno), errno);
		rv = -1;
		goto errout_silent;
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

	/* open kextctl if configured */
	if (cfg->kextlevel > 0) {
		if ((kefd = kextctl_open()) == -1) {
			fprintf(stderr, "kextctl_open() failed: %s (%i)\n",
			        strerror(errno), errno);
			fprintf(stderr, "Proceeding without kext\n");
			cfg->kextlevel = 0;
		} else {
			rv = kqueue_add_signal(SIGTSTP, &sigtstp_ctx);
			if (rv == -1) {
				fprintf(stderr, "kqueue_add_signal(SIGTSTP) "
				                "failed: %s (%i)\n",
				                strerror(errno), errno);
				rv = -1;
				goto errout_silent;
			}
		}
		/* from here on the kernel blocks execs until we ACK */
	}

	/* log xnumon start */
	if (log_event_xnumon_start() == -1) {
		fprintf(stderr, "log_event_xnumon_start() failed\n");
		rv = -1;
		goto errout_silent;
	}

	/* add kextctl to kqueue */
	if (kefd != -1) {
		rv = kqueue_add_fd_read(kefd, &kefd_ctx);
		if (rv == -1) {
			fprintf(stderr,
			        "kqueue_add_fd_read(/dev/xnumon) failed: "
			        "%s (%i)\n", strerror(errno), errno);
			rv = -1;
			goto errout;
		}
	}

	/* add auditpipe to kqueue */
	rv = kqueue_add_fd_read(fileno(auef), &auef_ctx);
	if (rv == -1) {
		fprintf(stderr, "kqueue_add_fd_read(/dev/auditpipe) failed: "
		                "%s (%i)\n", strerror(errno), errno);
		rv = -1;
		goto errout;
	}

	/* start stats timer */
	rv = kqueue_add_timer(1, cfg->stats_interval, &sttm_ctx);
	if (rv == -1) {
		fprintf(stderr, "kqueue_add_timer(1) failed: %s (%i)\n",
		                strerror(errno), errno);
		rv = -1;
		goto errout;
	}

	if (cfg->launchd_mode) {
		/* start config file timer */
		bzero(cfgattr, 2*sizeof(stat_attr_t));
		(void)stats_timer_fired(2, cfg);
		rv = kqueue_add_timer(2, 300, &cftm_ctx);
		if (rv == -1) {
			fprintf(stderr, "kqueue_add_timer(2) failed: %s (%i)\n",
			                strerror(errno), errno);
			rv = -1;
			goto errout;
		}
	}

	/* event dispatch loop */
	running = true;
	for (;;) {
		rv = kqueue_dispatch();
		if (rv != 0) {
			if (!running)
				break;
			fprintf(stderr, "kevent_dispatch() failed\n");
			rv = -1;
			goto errout;
		}
	}

	rv = 0;
errout:
	/* log xnumon stats and stop */
	(void)log_event_xnumon_stats();
	if (log_event_xnumon_stop() == -1) {
		fprintf(stderr, "log_event_xnumon_stop() failed\n");
		rv = -1;
		goto errout;
	}

errout_silent:
	kqueue_fini();
	if (kefd != -1) {
		close(kefd);
		kefd = -1;
	}
	if (auef) {
		fclose(auef);
		auef = NULL;
	}
	work_fini();            /* drain work queue */
	hackmon_fini();
	filemon_fini();
	procmon_fini();         /* clear kext queue */
	log_fini();             /* drain log queue */
	assert(procmon_images() == 0);
	os_fini();
	cacheldpl_fini();
	cachecsig_fini();
	cachehash_fini();
	return rv;
}

