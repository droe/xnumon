/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include "sched.h"

#include <mach/mach.h>
#include <mach/thread_policy.h>
#include <sys/resource.h>

int
policy_task_sched_priority(void) {
#if 0
	if (setpriority(PRIO_PROCESS, 0, -20) == -1) {
		fprintf(stderr, "Failed to set process priority to -20: "
		                "%s (%i)\n", strerror(errno), errno);
		rv = -1;
		goto errout;
	}
#endif

	kern_return_t krv;
	mach_port_t task = mach_task_self();

	struct task_category_policy cp = {
		TASK_FOREGROUND_APPLICATION
	};
	krv = task_policy_set(task,
	                      TASK_CATEGORY_POLICY,
	                      (task_policy_t)&cp,
	                      TASK_CATEGORY_POLICY_COUNT);
	if (krv != KERN_SUCCESS)
		return -1;

	/* the following requires Mavericks or later */
	struct task_qos_policy qp = {
		LATENCY_QOS_TIER_1,
		THROUGHPUT_QOS_TIER_1
	};
	krv = task_policy_set(task,
	                      TASK_OVERRIDE_QOS_POLICY,
	                      (task_policy_t)&qp,
	                      TASK_QOS_POLICY_COUNT);
	if (krv != KERN_SUCCESS)
		return -1;
	return 0;
}

/*
 * _terra pericolosa_
 * Fiddling with scheduling priorities directly seems to have adversary
 * effects more often than not.  It seems preferable to let the QOS policy
 * do its thing instead of tuning priorities.
 */
#if 0
int
policy_thread_sched_priority(int prio) {
	kern_return_t krv;

	struct thread_precedence_policy pp = {prio};
	krv = thread_policy_set(mach_thread_self(),
	                        THREAD_PRECEDENCE_POLICY,
	                        (thread_policy_t)&pp,
	                        THREAD_PRECEDENCE_POLICY_COUNT);
	if (krv != KERN_SUCCESS) {
		return -1;
	}
	return 0;
}

int
policy_thread_sched_standard(void) {
	kern_return_t krv;

	struct thread_standard_policy sp = {0};
	krv = thread_policy_set(mach_thread_self(),
                                THREAD_STANDARD_POLICY,
                                (thread_policy_t)&sp,
                                THREAD_STANDARD_POLICY_COUNT);
	if (krv != KERN_SUCCESS) {
		return -1;
	}
	return 0;
}
#endif

int
policy_thread_diskio_important(void) {
	return setiopolicy_np(IOPOL_TYPE_DISK,
	                      IOPOL_SCOPE_THREAD,
	                      IOPOL_IMPORTANT);
}

int
policy_thread_diskio_standard(void) {
	return setiopolicy_np(IOPOL_TYPE_DISK,
	                      IOPOL_SCOPE_THREAD,
	                      IOPOL_STANDARD);
}

int
policy_thread_diskio_utility(void) {
	return setiopolicy_np(IOPOL_TYPE_DISK,
	                      IOPOL_SCOPE_THREAD,
	                      IOPOL_UTILITY);
}

