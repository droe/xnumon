/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include "xnumon.h"
#include "xnumon_cdev.h"
#include "xnumon_kauth.h"

#include <libkern/libkern.h>
#include <libkern/OSMalloc.h>
#include <mach/mach_types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/uio.h>
#include <sys/fcntl.h>
#include <sys/poll.h>
#include <sys/conf.h>
#include <sys/lock.h>
#include <miscfs/devfs/devfs.h>
#include <IOKit/IOLib.h>

/*
 * Current protocol is to provide queued messages to userland in a traditional
 * BSD way, through the character special device's read syscall.  The userspace
 * daemon has to acknowledge each message by calling the ACK_COOKIE ioctl.
 * The cdev supports poll, select and kevent monitoring for readability of open
 * file descriptors to this device.
 *
 * While this is not the Apple-recommended way to do things, it has the
 * advantage that the resuling interface exposed to userspace is conceptually
 * similar to the interface provided by the OpenBSM auditpipe facility.
 */

/*
 * sizeof(struct selinfo) == 24     10.5 - 10.6/i386
 * sizeof(struct selinfo) == 48     10.6/x86_64, 10.10
 * sizeof(struct selinfo) == 64     10.11 - 10.13
 */
struct xnumon_cdev_selinfo {
	unsigned char space[64];
};

static struct {
	OSMallocTag     mtag;

	lck_grp_t       *lck_grp;
	lck_mtx_t       *lck_mtx;

	int dev_major;
	void *dev_handle;

	int state;
#define XNUMON_CDEV_STATE_DEAD  0 /* must be 0 */
#define XNUMON_CDEV_STATE_READY 1
#define XNUMON_CDEV_STATE_OPEN  2
	pid_t pid;
	pid_t kthrpid;

	int flags;
#define XNUMON_CDEV_FLAG_NBIO   0x00000001
#define XNUMON_CDEV_FLAG_ASYNC  0x00000002

	TAILQ_HEAD(, xnumon_cdev_entry) queue;
	unsigned long qlength;
	unsigned long qbytes;
	unsigned long qoffset;

	unsigned long qwaiters;
	struct xnumon_cdev_selinfo rsel;
	pid_t sigiopid;
} xnumon_cdev;

#define XNUMON_CDEV_MTX      xnumon_cdev.lck_mtx
#define XNUMON_CDEV_LOCK()   lck_mtx_lock(XNUMON_CDEV_MTX)
#define XNUMON_CDEV_UNLOCK() lck_mtx_unlock(XNUMON_CDEV_MTX)

struct xnumon_cdev_entry *
xnumon_cdev_entry_alloc(unsigned long sz) {
	struct xnumon_cdev_entry *entry;
	uint32_t toalloc;

	toalloc = sz + sizeof(struct xnumon_cdev_entry);
	if (toalloc < sz)
		return NULL;
	entry = OSMalloc(toalloc, xnumon_cdev.mtag);
	if (entry)
		entry->sz = sz;
	return entry;
}

void
xnumon_cdev_entry_free(struct xnumon_cdev_entry *entry) {
	OSFree(entry, sizeof(struct xnumon_cdev_entry) + entry->sz, xnumon_cdev.mtag);
}

/*
 * Enqueue a new record onto the cdev queue, ready for the userspace daemon to
 * retrieve.
 *
 * Note that there is no size limit on the queue.  The fact that the process
 * calling execve is blocked until it is released here means that there is a
 * natural limit on how many execve calls can be stuck in here at the same
 * time, and hence, the size of the queue.
 */
kern_return_t
xnumon_cdev_enqueue(struct xnumon_cdev_entry *entry) {
	if (xnumon_cdev.state == XNUMON_CDEV_STATE_DEAD)
		return KERN_TERMINATED;

	XNUMON_CDEV_LOCK();
	if (xnumon_cdev.state != XNUMON_CDEV_STATE_OPEN) {
		XNUMON_CDEV_UNLOCK();
		return KERN_TERMINATED;
	}
	TAILQ_INSERT_TAIL(&xnumon_cdev.queue, entry, queue);
	xnumon_cdev.qlength++;
	xnumon_cdev.qbytes += entry->sz;
	selwakeup((struct selinfo *)&xnumon_cdev.rsel);
	if (xnumon_cdev.flags & XNUMON_CDEV_FLAG_ASYNC)
		proc_signal(xnumon_cdev.sigiopid, SIGIO);
	if (xnumon_cdev.qwaiters > 0) {
		xnumon_cdev.qwaiters--;
		wakeup_one((caddr_t)&xnumon_cdev.queue);
	}
	XNUMON_CDEV_UNLOCK();

	return KERN_SUCCESS;
}

static int
xnumon_cdev_open(__attribute__((unused)) dev_t dev,
                 __attribute__((unused)) int flags,
                 __attribute__((unused)) int type,
                                         proc_t p) {
	if (xnumon_cdev.state == XNUMON_CDEV_STATE_DEAD)
		return ENXIO;

	XNUMON_CDEV_LOCK();
	if (xnumon_cdev.state != XNUMON_CDEV_STATE_READY) {
		XNUMON_CDEV_UNLOCK();
		return EBUSY;
	}
	xnumon_cdev.state = XNUMON_CDEV_STATE_OPEN;
	xnumon_cdev.pid = proc_pid(p);
	xnumon_kauth_start();
	XNUMON_CDEV_UNLOCK();

	printf(KEXTNAME_S ": " XNUMON_DEVPATH " opened by pid %d\n",
	       xnumon_cdev.pid);
	return 0;
}

static int
xnumon_cdev_close(__attribute__((unused)) dev_t dev,
                  __attribute__((unused)) int flags,
                  __attribute__((unused)) int type,
                                          proc_t p) {
	struct xnumon_cdev_entry *entry;

	if (xnumon_cdev.state == XNUMON_CDEV_STATE_DEAD)
		return (ENXIO);

	XNUMON_CDEV_LOCK();
	if (xnumon_cdev.state != XNUMON_CDEV_STATE_OPEN) {
		XNUMON_CDEV_UNLOCK();
		return EBADF;
	}

	xnumon_kauth_stop();
	xnumon_cdev.pid = 0;
	xnumon_cdev.state = XNUMON_CDEV_STATE_READY;

	/*
	 * This should not be needed.  Call wakeup anyway, in case something
	 * went very wrong and a thread is still stuck in the cdev.
	 */
	if (xnumon_cdev.qwaiters > 0) {
		xnumon_cdev.qwaiters = 0;
		wakeup((caddr_t)&xnumon_cdev.queue);
	}

	/* after xnumon_kauth_stop() above, all waiting threads have exited */
	while ((entry = TAILQ_FIRST(&xnumon_cdev.queue)) != NULL) {
		TAILQ_REMOVE(&xnumon_cdev.queue, entry, queue);
		xnumon_cdev.qbytes -= entry->sz;
		xnumon_cdev_entry_free(entry);
		xnumon_cdev.qlength--;
	}
	xnumon_cdev.qoffset = 0;

	XNUMON_CDEV_UNLOCK();
	printf(KEXTNAME_S ": " XNUMON_DEVPATH " closed by pid %d\n",
	       proc_pid(p));
	return 0;
}

static int
xnumon_cdev_ioctl(__attribute__((unused)) dev_t dev,
                                          u_long cmd,
                                          caddr_t data,
                  __attribute__((unused)) int flag,
                                          proc_t p) {
	unsigned long available;
	xnumon_stat_t *st;

	if (xnumon_cdev.state == XNUMON_CDEV_STATE_DEAD)
		return ENXIO;

	switch (cmd) {
	case FIONBIO:
		XNUMON_CDEV_LOCK();
		if (*(int *)data)
			xnumon_cdev.flags |= XNUMON_CDEV_FLAG_NBIO;
		else
			xnumon_cdev.flags &= ~XNUMON_CDEV_FLAG_NBIO;
		XNUMON_CDEV_UNLOCK();
		return 0;

	case FIONREAD:
		XNUMON_CDEV_LOCK();
		available = xnumon_cdev.qbytes - xnumon_cdev.qoffset;
		*(int *)data = (available > INT_MAX) ? INT_MAX : available;
		XNUMON_CDEV_UNLOCK();
		return 0;

	case FIOASYNC:
		XNUMON_CDEV_LOCK();
		if (*(int *)data) {
			xnumon_cdev.flags |= XNUMON_CDEV_FLAG_ASYNC;
			xnumon_cdev.sigiopid = proc_pid(p);
		} else {
			xnumon_cdev.flags &= ~XNUMON_CDEV_FLAG_ASYNC;
			xnumon_cdev.sigiopid = 0;
		}
		XNUMON_CDEV_UNLOCK();
		return 0;

	case XNUMON_ACK_COOKIE:
		xnumon_kauth_release(*(uint64_t *)data);
		return 0;

	case XNUMON_GET_STATS:
		st = (xnumon_stat_t*)data;
		xnumon_kauth_stats(&st->kauth_defers,
		                   &st->kauth_denies,
		                   &st->kauth_errors,
		                   &st->kauth_timeouts,
		                   &st->kauth_visitors);
		st->cdev_qsize = (uint32_t)xnumon_cdev.qlength;
		return 0;

	}

	return ENOTTY;
}

static int
xnumon_cdev_read(__attribute__((unused)) dev_t dev,
                                         uio_t uio,
                 __attribute__((unused)) int flags) {
	int error;
	u_int toread;
	struct xnumon_cdev_entry *entry;

retry:
	if (xnumon_cdev.state == XNUMON_CDEV_STATE_DEAD)
		return ENXIO;

	XNUMON_CDEV_LOCK();
	if (xnumon_cdev.state != XNUMON_CDEV_STATE_OPEN)
		return ENXIO;
	if (TAILQ_EMPTY(&xnumon_cdev.queue)) {
		if (xnumon_cdev.flags & XNUMON_CDEV_FLAG_NBIO) {
			XNUMON_CDEV_UNLOCK();
			return EAGAIN;
		}
		xnumon_cdev.qwaiters++;
		error = msleep(&xnumon_cdev.queue, XNUMON_CDEV_MTX,
		               PUSER|PDROP|PCATCH, KEXTNAME_S, NULL);
		if (error)
			return error;
		goto retry;
	}

	while ((entry = TAILQ_FIRST(&xnumon_cdev.queue)) != NULL &&
	       uio_resid(uio) > 0) {
		/* copy (remaining bytes) of first element to userspace */
		toread = MIN((user_ssize_t)(entry->sz - xnumon_cdev.qoffset),
		             uio_resid(uio));
		error = uiomove((char *)(entry->payload) + xnumon_cdev.qoffset,
		                toread, uio);
		if (error) {
			XNUMON_CDEV_UNLOCK();
			return error;
		}

		/* remove read data from queue */
		xnumon_cdev.qoffset += toread;
		if (xnumon_cdev.qoffset == entry->sz) {
			TAILQ_REMOVE(&xnumon_cdev.queue, entry, queue);
			xnumon_cdev.qbytes -= entry->sz;
			xnumon_cdev_entry_free(entry);
			xnumon_cdev.qlength--;
			xnumon_cdev.qoffset = 0;
		}
	}
	XNUMON_CDEV_UNLOCK();
	return 0;
}

static int
xnumon_cdev_select(__attribute__((unused)) dev_t dev,
                   int events, void *wql, proc_t p) {
	int revents = 0;

	if (xnumon_cdev.state == XNUMON_CDEV_STATE_DEAD)
		return (revents);

	if (events & (POLLIN | POLLRDNORM)) {
		XNUMON_CDEV_LOCK();
		if (TAILQ_FIRST(&xnumon_cdev.queue) != NULL)
			revents |= events & (POLLIN | POLLRDNORM);
		else
			selrecord(p, (struct selinfo *)&xnumon_cdev.rsel, wql);
		XNUMON_CDEV_UNLOCK();
	}
	return revents;
}

static struct cdevsw dev_fops = {
	.d_open = xnumon_cdev_open,
	.d_close = xnumon_cdev_close,
	.d_read = xnumon_cdev_read,
	.d_ioctl = xnumon_cdev_ioctl,
	.d_select = xnumon_cdev_select,
};

static void
xnumon_cdev_free(void) {
	KASSERT(xnumon_cdev.state == XNUMON_CDEV_STATE_DEAD,
	        ("xnumon_cdev_free: xnumon_cdev.state != DEAD"));

	if (xnumon_cdev.dev_handle) {
		devfs_remove(xnumon_cdev.dev_handle);
	}
	if (xnumon_cdev.dev_major != -1) {
		cdevsw_remove(xnumon_cdev.dev_major, &dev_fops);
	}

	if (xnumon_cdev.lck_mtx) {
		lck_mtx_free(xnumon_cdev.lck_mtx, xnumon_cdev.lck_grp);
		xnumon_cdev.lck_mtx = NULL;
	}
	if (xnumon_cdev.lck_grp) {
		lck_grp_free(xnumon_cdev.lck_grp);
		xnumon_cdev.lck_grp = NULL;
	}

	if (xnumon_cdev.mtag) {
		OSMalloc_Tagfree(xnumon_cdev.mtag);
		xnumon_cdev.mtag = NULL;
	}
}

kern_return_t
xnumon_cdev_start(void) {
	bzero(&xnumon_cdev, sizeof(xnumon_cdev));
	/* implicitly sets state to DEAD */

	TAILQ_INIT(&xnumon_cdev.queue);

	xnumon_cdev.mtag = OSMalloc_Tagalloc(BUNDLEID_S ".cdev", OSMT_DEFAULT);
	if (!xnumon_cdev.mtag) {
		printf(KEXTNAME_S ": OSMalloc_Tagalloc failed\n");
		return KERN_FAILURE;
	}

	xnumon_cdev.lck_grp = lck_grp_alloc_init(BUNDLEID_S ".cdev",
	                                         LCK_GRP_ATTR_NULL);
	if (!xnumon_cdev.lck_grp) {
		printf(KEXTNAME_S ": lck_grp_alloc_init failed\n");
		xnumon_cdev_free();
		return KERN_FAILURE;
	}
	xnumon_cdev.lck_mtx = lck_mtx_alloc_init(xnumon_cdev.lck_grp,
	                                         LCK_ATTR_NULL);
	if (!xnumon_cdev.lck_mtx) {
		printf(KEXTNAME_S ": lck_mtx_alloc_init failed\n");
		xnumon_cdev_free();
		return KERN_FAILURE;
	}

	xnumon_cdev.dev_major = cdevsw_add(-1, &dev_fops);
	if (xnumon_cdev.dev_major == -1) {
		printf(KEXTNAME_S ": cdevsw_add failed\n");
		xnumon_cdev_free();
		return KERN_FAILURE;
	}
	xnumon_cdev.dev_handle = \
	        devfs_make_node(makedev(xnumon_cdev.dev_major, 0), DEVFS_CHAR,
	                        UID_ROOT, GID_WHEEL, 0660, XNUMON_DEVNAME, 0);
	if (!xnumon_cdev.dev_handle) {
		printf(KEXTNAME_S ": devfs_make_node failed\n");
		xnumon_cdev_free();
		return KERN_FAILURE;
	}

	xnumon_cdev.state = XNUMON_CDEV_STATE_READY;
	return KERN_SUCCESS;
}

kern_return_t
xnumon_cdev_stop(void) {
	if (xnumon_cdev.state == XNUMON_CDEV_STATE_DEAD)
		return KERN_SUCCESS;

	XNUMON_CDEV_LOCK();
	if (xnumon_cdev.state != XNUMON_CDEV_STATE_READY) {
		XNUMON_CDEV_UNLOCK();
		return KERN_FAILURE;
	}
	xnumon_cdev.state = XNUMON_CDEV_STATE_DEAD;
	XNUMON_CDEV_UNLOCK();

	xnumon_cdev_free();
	return KERN_SUCCESS;
}

/*
 * Perform termination of a process as a separate kernel thread.
 * The process is first terminated gracefully (SIGTERM) and given time to
 * terminate gracefully, but if that fails and it is still not exiting 10
 * seconds later, it is being killed forcefully (SIGKILL).
 */
static void
xnumon_cdev_killthr(void *thrarg) {
	pid_t pid = *(pid_t*)thrarg;
	proc_t proc;

	proc = proc_find(pid);
	if (!proc)
		return;
	printf(KEXTNAME_S ": sending SIGTERM to pid %d\n", pid);
	proc_signal(pid, SIGTERM);
	IOSleep(10000);
	if (!proc_exiting(proc)) {
		printf(KEXTNAME_S ": pid %d not exiting 10s after SIGTERM, "
		       "sending SIGKILL\n", pid);
		proc_signal(pid, SIGKILL);
	}
	proc_rele(proc);
}

/*
 * Terminate the attached client after too many timeouts or errors.
 * This is a precaution in order to keep the system operational when things
 * go horribly wrong.  It should not happen under normal circumstances, but
 * when it happens, it is important that we do not stall the system by
 * blocking all execs.  The actual termination is done in a separate thread.
 */
void
xnumon_cdev_kill(void) {
	pid_t pid;
	thread_t kthr;

	pid = xnumon_cdev.pid;
	if (pid > 0) {
		xnumon_cdev.pid = 0;
		xnumon_cdev.kthrpid = pid;
		if (kernel_thread_start((thread_continue_t)xnumon_cdev_killthr,
		                        &xnumon_cdev.kthrpid,
		                        &kthr) == KERN_SUCCESS) {
			thread_deallocate(kthr);
		} else {
			printf(KEXTNAME_S ": failed to start killthr, "
			       "sending SIGKILL to %d immediately\n", pid);
			proc_signal(pid, SIGKILL);
		}
	}
}

