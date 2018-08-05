/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include <unistd.h>
#include <stdio.h>
#include <signal.h>

int
main(int argc, char *argv[]) {
	pid_t pid;

	printf("spec:testcase returncode=0\n");
	fflush(stdout);

	pid = fork();
	if (pid == -1) {
		perror("fork");
		return 1;
	} else if (pid == 0) {
		/* child */
		for (;;);
	}
	/* parent */
	printf("%i self\n", pid);
	kill(pid, SIGSTOP);
	sleep(1);
	kill(pid, SIGCONT);
	sleep(1);
	kill(pid, SIGTERM);

	printf("spec:image-exec "
	       "subject.pid=%i "
	       "\n", getpid());
	printf("spec:absent:image-exec "
	       "subject.pid=%i "
	       "\n", pid);

	return 0;
}

