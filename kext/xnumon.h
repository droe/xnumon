/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2019, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

/*
 * Userspace and kernel headers for the /dev/xnumon msg and ioctl interface.
 *
 * The basic model consists of the userspace daemon reading variable-length
 * xnumon_msg_t records from /dev/xnumon and acknowledging each processed
 * message individually using the XNUMON_ACK_COOKIE ioctl.  The kext will block
 * the process calling execve until it receives the ACK for the respective
 * message from userspace.
 */

#ifndef KEXT_XNUMON_H
#define KEXT_XNUMON_H

#ifdef KERNEL
#include <mach/mach_types.h>
#else /* !KERNEL */
#include <sys/ioctl.h>
#include <stdint.h>
#endif /* !KERNEL */

typedef struct __attribute__((packed)) {
	uint64_t kauth_timeouts;
	uint64_t kauth_errors;
	uint64_t kauth_defers;
	uint64_t kauth_denies;
	uint32_t kauth_visitors;
	uint32_t cdev_qsize;
} xnumon_stat_t;

#define XNUMON_IOBASE           'X'
#define XNUMON_ACK_COOKIE       _IOW(XNUMON_IOBASE, 1, uint64_t)
#define XNUMON_GET_STATS        _IOR(XNUMON_IOBASE, 2, xnumon_stat_t)

typedef struct __attribute__((packed)) {
	uint16_t version;
	uint16_t msgsz;
	uint32_t pid;
	uint64_t cookie;
	uint64_t time_s;
	uint64_t time_ns;
	char path[];
} xnumon_msg_t;

#define XNUMON_MSG_VERSION      1
#define XNUMON_MAXPATHLEN       1024
#define XNUMON_MSG_HDR          sizeof(xnumon_msg_t)
#define XNUMON_MSG_MIN          sizeof(xnumon_msg_t) + 1
#define XNUMON_MSG_MAX          sizeof(xnumon_msg_t) + XNUMON_MAXPATHLEN
#define XNUMON_DEVNAME          "xnumon"
#define XNUMON_DEVPATH          "/dev/" XNUMON_DEVNAME
#define XNUMON_BUNDLEID         "ch.roe.kext.xnumon"

#endif

