#include <stdio.h>
#include <unistd.h>
#include <spawn.h>

#include <mach/mach.h>

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

