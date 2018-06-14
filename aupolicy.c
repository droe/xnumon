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
 * not set in the kernel yet.  Print a warning message to stdout if the kernel
 * had a different setting than requested.
 */
int
aupolicy_ensure(int policy) {
	int rv;
	int kpolicy;

	rv = audit_get_policy(&kpolicy);
	if (rv != 0)
		return -1;
	if ((kpolicy & policy) != policy) {
		fprintf(stderr,
		        "The following audit policy flags are needed "
		        "by the current configuration,\n"
		        "but were not already enabled in the kernel: ");
		if ((policy & AUDIT_ARGV) && !(kpolicy & AUDIT_ARGV))
			fprintf(stderr, "argv");
		if ((policy & AUDIT_ARGE) && !(kpolicy & AUDIT_ARGE))
			fprintf(stderr, "arge");
		fprintf(stderr,
		        "\nTo prevent auditd from clobbering them in"
		        " the kernel, make sure that\n"
		        "/etc/security/audit_control includes all policy"
		        " flags required by the current\n"
		        "configuration: %s %s\n",
		        (policy & AUDIT_ARGV) ? "argv" : "",
		        (policy & AUDIT_ARGE) ? "arge" : "");
	}
	kpolicy |= policy;
	rv = audit_set_policy(&kpolicy);
	if (rv != 0)
		return -1;
	return 0;
}

