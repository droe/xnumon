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
#include <sys/ptrace.h>

#include "path.h"

#define PATH TESTDIR"/true.dep"
#define ARGV0 "true.dep"

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
	printf("spec:process-access "
	       "subject.pid=%i "
	       "subject.image.path=%s "
	       "object.pid=%i "
	       "object.image.path="PATH" "
	       "method=ptrace "
	       "\n",
	       getpid(), getpath(), pid);

	if (ptrace(PT_ATTACHEXC, pid, NULL, 0) == -1) {
		perror("ptrace(PT_ATTACHEXC)");
		kill(pid, SIGCONT);
		return 1;
	}
	sleep(1);
	/* we're supposed to implement complicated Mach exception handling
	 * in order to detach properly from the ptraced process; skip that
	 * and simply kill it the hard way, not waiting for an exit status */
	kill(pid, SIGCONT);
	kill(pid, SIGKILL);
	return 0;
}

