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
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <mach/mach.h>

#include "path.h"

#define PATH TESTDIR"/true.dep"
#define ARGV0 "true.dep"

/*
 * task_for_pid() and processor_set_tasks() fail on binaries signed by Apple.
 * On unsigned binaries, it works for root or special code signing magic.
 * http://os-tres.net/blog/2010/02/17/mac-os-x-and-task-for-pid-mach-call/
 * http://devstreaming.apple.com/videos/wwdc/2015/706nu20qkag/706/706_security_and_your_apps.pdf
 *
 * Note that processor_set_default() returns only the task port of the current
 * process on macOS 10.14+.
 */

mach_error_t
alt_task_for_pid(pid_t pid, mach_port_t *taskport)
{
	mach_port_t procset;
	mach_port_t procsetctl;
	task_array_t taskarr;
	mach_msg_type_number_t taskcount;
	kern_return_t kr;
	host_t host = mach_host_self();

	kr = processor_set_default(host, &procset);
	if (kr != KERN_SUCCESS) {
		fprintf(stderr, "processor_set_default: %i\n", kr);
		return kr;
	}
	kr = host_processor_set_priv(host, procset, &procsetctl);
	if (kr != KERN_SUCCESS) {
		fprintf(stderr, "host_processor_set_priv: %i\n", kr);
		return kr;
	}
	kr = processor_set_tasks(procsetctl, &taskarr, &taskcount);
	if (kr != KERN_SUCCESS) {
		fprintf(stderr, "processor_set_tasks: %i\n", kr);
		return kr;
	}

	kr = 0;
	for (size_t i = 0; i < taskcount; i++) {
		pid_t taskpid;
		pid_for_task(taskarr[i], &taskpid);
		fprintf(stderr, "received task for pid %i\n", taskpid);
		if (taskpid == pid) {
			*taskport = taskarr[i];
			kr = KERN_SUCCESS;
			continue;
		}
		mach_port_deallocate(mach_task_self(), taskarr[i]);
	}
	return kr;
}

/*
 * Real process hollowing would use mach_vm_map, mach_vm_unmap, mach_vm_read,
 * mach_vm_write or other calls to inject code into the task, from just
 * patching some instructions to loading code from a Mach-O.
 *
 * Instead, just dump memory regions for now, not handling subregions.
 * Since a successful acquisition of send rights to the task port effectively
 * gives full power over the task, this is sufficient for testing.
 */
void
hack_suspended_process(task_t taskport) {
	vm_address_t address;
	vm_size_t size;

	for (address = VM_MIN_ADDRESS;; address += size) {
		kern_return_t kr;
		struct vm_region_basic_info_64 info;
		mach_msg_type_number_t info_cnt = VM_REGION_BASIC_INFO_COUNT_64;
		mach_port_t obj_name;
		kr = vm_region_64(taskport, &address, &size,
		                  VM_REGION_BASIC_INFO_64,
		                  (vm_region_info_t)&info, &info_cnt,
		                  &obj_name);
		if (obj_name != MACH_PORT_NULL)
			mach_port_deallocate(mach_task_self(), obj_name);
		if (kr != KERN_SUCCESS)
			break;
		printf("%016lx-%016lx %s%s%s\n", address, address + size - 1,
		       (info.protection & VM_PROT_READ)    ? "r" : "-",
		       (info.protection & VM_PROT_WRITE)   ? "w" : "-",
		       (info.protection & VM_PROT_EXECUTE) ? "x" : "-");
	}
}

int
main(int argc, char *argv[]) {
	int rv;
	pid_t pid;
	char *av[] = {ARGV0, NULL};
	char *ev[] = {NULL};
	posix_spawnattr_t attr;

	printf("spec:testcase returncode=0\n");
	fflush(stdout);

	rv = posix_spawnattr_init(&attr);
	if (rv != 0) {
		errno = rv;
		perror("posix_spawnattr_init");
	}
	rv = posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);
	if (rv != 0) {
		errno = rv;
		perror("posix_spawnattr_setflags");
	}
	rv = posix_spawn(&pid, PATH, NULL, NULL, av, ev);
	if (rv == -1) {
		perror("spawn");
		return 1;
	}

	printf("spec:image-exec "
	       "subject.pid=%i "
	       "subject.image.path=%s "
	       "image.path="PATH" "
	       "argv="ARGV0
	       "\n",
	       pid, getpath());
	printf("spec:radar40755284:process-access "
	       "subject.pid=%i "
	       "subject.image.path=%s "
	       "object.pid=%i "
	       "object.image.path="PATH" "
	       /* "method=processor_set_tasks " */
	       "\n",
	       getpid(), getpath(), pid);

	task_t port;
	mach_error_t err;

	err = alt_task_for_pid(pid, &port);
	if (err) {
		fprintf(stderr, "alt_task_for_pid failed\n");
		kill(pid, SIGCONT);
		return 1;
	}

	hack_suspended_process(port);
	task_resume(port);
	mach_port_deallocate(mach_task_self(), port);

	int status;
	waitpid(pid, &status, 0);
	return WEXITSTATUS(status);
}

