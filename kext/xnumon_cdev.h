/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef XNUMON_CDEV_H
#define XNUMON_CDEV_H

#include <mach/mach_types.h>
#include <sys/queue.h>

#define XNUMON_IOBASE           'X'
#define XNUMON_ACK_COOKIE       _IOW(XNUMON_IOBASE, 1, uint64_t)
#if 0
#define XNUMON_GET_STATS        _IOR(XNUMON_IOBASE, 2, u_int)
#endif

struct xnumon_cdev_entry {
	TAILQ_ENTRY(xnumon_cdev_entry) queue;
	unsigned long sz;
	unsigned char payload[];
};

struct xnumon_cdev_entry * xnumon_cdev_entry_alloc(unsigned long);
void xnumon_cdev_entry_free(struct xnumon_cdev_entry *);
kern_return_t xnumon_cdev_enqueue(struct xnumon_cdev_entry *);
void xnumon_cdev_kill(void);
kern_return_t xnumon_cdev_start(void);
kern_return_t xnumon_cdev_stop(void);

#endif

