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

#include "getpath.h"

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
	printf("spec:2:process-access "
	       "subject.pid=%i "
	       "subject.image.path=%s "
	       "object.pid=%i "
	       "object.image.path="PATH" "
	       "method=ptrace "
	       "\n",
	       getpid(), getpath(), pid);

	if (ptrace(PT_ATTACHEXC, pid, NULL, 0) == -1) {
		perror("ptrace");
		kill(pid, SIGCONT);
		return 1;
	}

	ptrace(PT_DETACH, pid, NULL, 0);
	kill(pid, SIGCONT);

	int status;
	waitpid(pid, &status, 0);
	return WEXITSTATUS(status);
}

