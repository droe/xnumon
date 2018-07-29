/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include "aupolicy.h"

/*
 * Check on the kernel's audit policy and enable the bits in policy that are
 * not set in the kernel yet.  Print a warning message to stderr if the kernel
 * had a different setting than requested.
 *
 * Returns -1 on error, 0 if no changes were needed, 1 if changes were needed.
 */
int
aupolicy_ensure(int policy) {
	int kpolicy;

	if (audit_get_policy(&kpolicy) != 0)
		return -1;
	if ((kpolicy & policy) == policy)
		return 0;
	fprintf(stderr,
	        "The following audit policy flags are needed "
	        "by the current configuration,\n"
	        "but were not already enabled in the kernel:");
	if ((policy & AUDIT_ARGV) && !(kpolicy & AUDIT_ARGV))
		fprintf(stderr, " argv");
	if ((policy & AUDIT_ARGE) && !(kpolicy & AUDIT_ARGE))
		fprintf(stderr, " arge");
	fprintf(stderr,
	        "\nTo prevent auditd from clobbering them in"
	        " the kernel, make sure that\n"
	        "/etc/security/audit_control includes all policy"
	        " flags required by the current\n"
	        "configuration:%s%s\n",
	        (policy & AUDIT_ARGV) ? " argv" : "",
	        (policy & AUDIT_ARGE) ? " arge" : "");
	kpolicy |= policy;
	if (audit_set_policy(&kpolicy) != 0)
		return -1;
	return 1;
}

