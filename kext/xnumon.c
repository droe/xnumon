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

#include <libkern/libkern.h>
#include <mach/mach_types.h>

kern_return_t
xnumon_start(__attribute((unused)) kmod_info_t *ki,
             __attribute((unused)) void *d) {
	kern_return_t krv;

	krv = xnumon_cdev_start();
	if (krv != KERN_SUCCESS)
		return krv;

	printf(KEXTNAME_S ": " KEXTBUILD_S " started, providing "
	       "XNUMON_MSG_VERSION %d\n", XNUMON_MSG_VERSION);
	return KERN_SUCCESS;
}

kern_return_t
xnumon_stop(__attribute__((unused)) kmod_info_t *ki,
            __attribute__((unused)) void *d) {
	kern_return_t krv;

	krv = xnumon_cdev_stop();
	if (krv != KERN_SUCCESS)
		return krv;

	printf(KEXTNAME_S ": " KEXTBUILD_S " stopped\n");
	return KERN_SUCCESS;
}

extern kern_return_t _start(kmod_info_t *ki, void *d);
extern kern_return_t _stop(kmod_info_t *ki, void *d);

KMOD_EXPLICIT_DECL(BUNDLEID, KEXTBUILD_S, _start, _stop)
__private_extern__ kmod_start_func_t *_realmain = xnumon_start;
__private_extern__ kmod_stop_func_t *_antimain = xnumon_stop;
__private_extern__ int _kext_apple_cc = __APPLE_CC__;

