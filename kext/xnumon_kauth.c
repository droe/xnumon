/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2019, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include "xnumon_cdev.h"
#include "xnumon.h"

#include <libkern/libkern.h>
#include <libkern/OSAtomic.h>
#include <mach/mach_types.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/kauth.h>
#include <sys/random.h>
#include <kern/thread.h>

static struct {
	int active;
	SInt32 visitors;

#define TIMEOUT_DSEC 10
	SInt32 check_errors;
	SInt32 next_check;
#define CHECK_EVERY 10
#define CHECK_LIMIT 5

	SInt64 defers;
	SInt64 denies;
	SInt64 errors;
	SInt64 timeouts;

	/* Note that the mutex is only used for msleeping in the callback,
	 * not for protecting this data structure. */
	lck_grp_t *lck_grp;
	lck_mtx_t *lck_mtx;

	kauth_listener_t vnode_listener;

	/* random cookie mask to avoid leaking kernel addresses to userspace */
	uint64_t cookie_mask;
} xnumon_kauth;

#define XNUMON_KAUTH_MTX      xnumon_kauth.lck_mtx
#define XNUMON_KAUTH_LOCK()   lck_mtx_lock(XNUMON_KAUTH_MTX)
#define XNUMON_KAUTH_UNLOCK() lck_mtx_unlock(XNUMON_KAUTH_MTX)

kern_return_t xnumon_kauth_stop(void);

/*
 * KAuth KAUTH_SCOPE_VNODE callback.
 *
 * This is a very hot callback.  Try to leave quickly for events we are not
 * interested in and avoid event feedback loops with the userspace daemon.
 *
 * For scripts, this is called twice, first for the script, then a second
 * time for the interpreter.
 */
static int
xnumon_kauth_vnode_cb(__attribute__((unused)) kauth_cred_t cred,
                      __attribute__((unused)) void *idata,
                                              kauth_action_t action,
                                              uintptr_t arg0, /* vfs context */
                                              uintptr_t arg1, /* first vnode */
                      __attribute__((unused)) uintptr_t arg2, /* second vnode */
                                              uintptr_t arg3) /* errno ptr */ {
	vfs_context_t ctx = (vfs_context_t)arg0;
	vnode_t vp = (vnode_t)arg1;
	int *errno = (int *)arg3;

	struct xnumon_cdev_entry *entry;
	xnumon_msg_t *msg;
	char path[MAXPATHLEN] = {0};
	int pathlenz = MAXPATHLEN;
	uint64_t kcookie;
	struct timespec tm;
	int error;

	_Static_assert(MAXPATHLEN <= XNUMON_MAXPATHLEN,
	               "MAXPATHLEN <= XNUMON_MAXPATHLEN");

	OSIncrementAtomic(&xnumon_kauth.visitors);

	if (!(action & KAUTH_VNODE_EXECUTE) || (action & KAUTH_VNODE_ACCESS))
		goto outunseen;

	if (!vp || !vnode_isreg(vp))
		goto outunseen;

	if (!xnumon_kauth.active)
		goto outunseen;

	error = vn_getpath(vp, path, &pathlenz);
	if (error == ENOSPC) {
		/* deny execution of executables with paths longer than
		 * MAXPATHLEN - there seems to be no way this can happen
		 * through Finder and even when calling execve or using the
		 * shell, you need to use a relative path with a cwd that
		 * combined result in a path longer than MAXPATHLEN. */
		printf(KEXTNAME_S ": kauth: denying execution because path"
		       " length > MAXPATHLEN\n");
		*errno = ENAMETOOLONG;
		goto outdeny;
	} else if (error != KERN_SUCCESS) {
		printf(KEXTNAME_S ": kauth: vn_getpath() failed\n");
		OSIncrementAtomic(&xnumon_kauth.check_errors);
		OSIncrementAtomic64(&xnumon_kauth.errors);
		goto out;
	}

	/* dyld is executed as part of loading images into processes and
	 * audit(4) generates no audit record either, therefore skip it */
	if (!strcmp(path, "/usr/lib/dyld"))
		goto outunseen;

	kcookie = (uint64_t)current_thread();
	_Static_assert(sizeof(thread_t) <= sizeof(uint64_t),
	               "sizeof(thread_t) <= sizeof(uint64_t)");
	nanotime(&tm);

	entry = xnumon_cdev_entry_alloc(sizeof(*msg) + pathlenz);
	if (!entry) {
		printf(KEXTNAME_S ": kauth: xnumon_cdev_entry_alloc() "
		       "failed\n");
		OSIncrementAtomic(&xnumon_kauth.check_errors);
		OSIncrementAtomic64(&xnumon_kauth.errors);
		goto out;
	}
	msg = (void*)entry->payload;
	msg->version = XNUMON_MSG_VERSION;
	msg->msgsz = entry->sz;
	msg->pid = vfs_context_pid(ctx);
	_Static_assert(sizeof(pid_t) <= sizeof(msg->pid),
	               "sizeof(pid_t) <= sizeof(msg->pid)");
	msg->cookie = kcookie ^ xnumon_kauth.cookie_mask;
	/* auditpipe time resolution is microseconds, not nanoseconds */
	msg->time_s = tm.tv_sec;
	msg->time_ns = tm.tv_nsec - (tm.tv_nsec % 1000);
	strncpy(msg->path, path, entry->sz - sizeof(*msg));
	if (xnumon_cdev_enqueue(entry) != KERN_SUCCESS) {
		xnumon_cdev_entry_free(entry);
		printf(KEXTNAME_S ": kauth: xnumon_cdev_enqueue() failed\n");
		OSIncrementAtomic(&xnumon_kauth.check_errors);
		OSIncrementAtomic64(&xnumon_kauth.errors);
		goto out;
	}

	size_t count = 0;
	while (xnumon_kauth.active) {
		/* sleep in decisecond intervals */
		struct timespec tv;
		tv.tv_sec = 0;
		tv.tv_nsec = 100000000;
		XNUMON_KAUTH_LOCK();
		error = msleep((caddr_t)kcookie, XNUMON_KAUTH_MTX,
		               PUSER|PDROP, KEXTNAME_S, &tv);
		if (!xnumon_kauth.active) {
			goto outunseen;
		}
		if (error == EWOULDBLOCK) {
			if (count++ > TIMEOUT_DSEC) {
				/* count timeout as an error for checking */
				OSIncrementAtomic(&xnumon_kauth.check_errors);
				OSIncrementAtomic64(&xnumon_kauth.timeouts);
				printf(KEXTNAME_S ": kauth: timeout\n");
				goto out;
			}
			continue;
		}
		if (error) {
			OSIncrementAtomic(&xnumon_kauth.check_errors);
			OSIncrementAtomic64(&xnumon_kauth.errors);
		}
		goto out;
	}

out:
	/* resetting errors to 0 is racy in a non-fatal way */
	if (OSCompareAndSwap(0, CHECK_EVERY - 1, &xnumon_kauth.next_check)) {
		if (xnumon_kauth.check_errors > CHECK_LIMIT) {
			OSDecrementAtomic(&xnumon_kauth.visitors);
			/* would be a race if _stop() would not wait until
			 * callback is drained or if _start() could be called
			 * while daemon is attached */
			xnumon_kauth_stop();
			xnumon_cdev_kill();
			printf(KEXTNAME_S ": kauth: exceeded %d errors per "
			       "%d KAuth callbacks, killed attached process\n",
			       CHECK_LIMIT, CHECK_EVERY);
			OSIncrementAtomic64(&xnumon_kauth.defers);
			return KAUTH_RESULT_DEFER;
		}
		xnumon_kauth.check_errors = 0;
	} else {
		OSDecrementAtomic(&xnumon_kauth.next_check);
	}
	OSIncrementAtomic64(&xnumon_kauth.defers);
outunseen:
	OSDecrementAtomic(&xnumon_kauth.visitors);
	return KAUTH_RESULT_DEFER;
outdeny:
	OSIncrementAtomic64(&xnumon_kauth.denies);
	OSDecrementAtomic(&xnumon_kauth.visitors);
	return KAUTH_RESULT_DENY;
}

void
xnumon_kauth_release(uint64_t ucookie) {
	wakeup((caddr_t)(ucookie ^ xnumon_kauth.cookie_mask));
}

void
xnumon_kauth_stats(uint64_t *defers, uint64_t *denies,
                   uint64_t *errors, uint64_t *timeouts,
                   uint32_t *visitors) {
	*defers   = (uint64_t)xnumon_kauth.defers;
	*denies   = (uint64_t)xnumon_kauth.denies;
	*errors   = (uint64_t)xnumon_kauth.errors;
	*timeouts = (uint64_t)xnumon_kauth.timeouts;
	*visitors = (uint32_t)xnumon_kauth.visitors;
}

static void
xnumon_kauth_free(void) {
	KASSERT(xnumon_kauth.active == 0,
	        "xnumon_kauth_free: xnumon_kauth.active != 0");

	if (xnumon_kauth.lck_mtx) {
		lck_mtx_free(xnumon_kauth.lck_mtx, xnumon_kauth.lck_grp);
		xnumon_kauth.lck_mtx = NULL;
	}
	if (xnumon_kauth.lck_grp) {
		lck_grp_free(xnumon_kauth.lck_grp);
		xnumon_kauth.lck_grp = NULL;
	}
}

kern_return_t
xnumon_kauth_start(void) {
	if (xnumon_kauth.active)
		return KERN_FAILURE;

	bzero(&xnumon_kauth, sizeof(xnumon_kauth));

	xnumon_kauth.lck_grp = lck_grp_alloc_init(BUNDLEID_S ".kauth",
	                                          LCK_GRP_ATTR_NULL);
	if (!xnumon_kauth.lck_grp) {
		printf(KEXTNAME_S ": lck_grp_alloc_init failed\n");
		xnumon_kauth_free();
		return KERN_FAILURE;
	}

	xnumon_kauth.lck_mtx = lck_mtx_alloc_init(xnumon_kauth.lck_grp,
	                                          LCK_ATTR_NULL);
	if (!xnumon_kauth.lck_mtx) {
		printf(KEXTNAME_S ": lck_mtx_alloc_init failed\n");
		xnumon_kauth_free();
		return KERN_FAILURE;
	}

	read_random(&xnumon_kauth.cookie_mask,
	            sizeof(xnumon_kauth.cookie_mask));

	xnumon_kauth.active = 1;
	xnumon_kauth.next_check = CHECK_EVERY;
	xnumon_kauth.vnode_listener = kauth_listen_scope(KAUTH_SCOPE_VNODE,
	                                                 xnumon_kauth_vnode_cb,
	                                                 NULL);
	if (xnumon_kauth.vnode_listener == NULL) {
		xnumon_kauth.active = 0;
		printf(KEXTNAME_S ": kauth_listen_scope() failed\n");
		xnumon_kauth_free();
		return KERN_FAILURE;
	}
	return KERN_SUCCESS;
}

kern_return_t
xnumon_kauth_stop(void) {
	if (!xnumon_kauth.active)
		return KERN_SUCCESS;

	xnumon_kauth.active = 0;
	if (xnumon_kauth.vnode_listener != NULL) {
		kauth_unlisten_scope(xnumon_kauth.vnode_listener);
		xnumon_kauth.vnode_listener = NULL;
	}

	do {
		struct timespec tv;
		tv.tv_sec = 0;
		tv.tv_nsec = 200000000;
		msleep(&xnumon_kauth.visitors, NULL, PUSER, KEXTNAME_S, &tv);
	} while (xnumon_kauth.visitors > 0);

	xnumon_kauth_free();
	return KERN_SUCCESS;
}

