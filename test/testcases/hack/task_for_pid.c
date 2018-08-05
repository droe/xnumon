#include <stdio.h>
#include <unistd.h>
#include <spawn.h>
#include <signal.h>
#include <errno.h>

#include <sys/types.h>
#include <mach/mach.h>

/*
 * task_for_pid() always fails on binaries signed by Apple.
 * On unsigned binaries, it works for root or special code signing magic.
 * http://os-tres.net/blog/2010/02/17/mac-os-x-and-task-for-pid-mach-call/
 */

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
	char *av[] = {"true", NULL};
	char *ev[] = {NULL};
	posix_spawnattr_t attr;

	printf("%i\n", getpid());

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
	rv = posix_spawn(&pid, "./true.dep", NULL, NULL, av, ev);
	if (rv == -1) {
		perror("spawn");
		return 1;
	}
	printf("%i ./true.dep\n", pid);

	task_t port;
	mach_error_t err;

	err = task_for_pid(mach_task_self(), pid, &port);
	if (err) {
		fprintf(stderr, "task_for_pid: %i\n", err);
		kill(pid, SIGCONT);
		return 1;
	}

	hack_suspended_process(port);
	task_resume(port);
	mach_port_deallocate(mach_task_self(), port);

	return 0;
}

