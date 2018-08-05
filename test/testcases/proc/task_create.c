/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include <stdio.h>
#include <unistd.h>
#include <spawn.h>

#include <mach/mach.h>

#include "getpath.h"

/*
 * For completeness, verify that task_create() always fails.
 * https://github.com/apple/darwin-xnu/blob/master/osfmk/kern/task.c
 */

int
main(int argc, char *argv[]) {
	kern_return_t kr;
	ledger_t ledger;
	ledger_array_t ledger_array;
	mach_msg_type_number_t ledger_count;
	task_t child_task;

	printf("spec:testcase returncode=1\n");
	printf("spec:absent:image-exec "
	       "subject.pid=%i "
	       "subject.image.path=%s "
	       "\n", getpid(), getpath());
	fflush(stdout);

	ledger_count = 1;
	ledger = (ledger_t)0;
	ledger_array = &ledger;
	kr = task_create(mach_task_self(), ledger_array, ledger_count, FALSE,
	                 &child_task);
	if (kr != KERN_SUCCESS) {
		mach_error("task_create:", kr);
		return 1;
	}

	return 0;
}

