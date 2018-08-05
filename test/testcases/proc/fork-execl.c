#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "getpath.h"

#define PATH "/usr/bin/true"
#define ARGV0 "true"

int
main(int argc, char *argv[]) {
	pid_t pid;

	pid = fork();
	if (pid == -1) {
		perror("fork");
		return 1;
	} else if (pid == 0) {
		/* child */
		execl(PATH, ARGV0, (char*)0);
		perror("exec");
		return 1;
	}
	/* parent */
	printf("spec:image-exec "
	       "subject.pid=%i "
	       "subject.image.path=%s "
	       "image.path="PATH" "
	       "argv="ARGV0
	       "\n",
	       pid, getpath());

	int status;
	waitpid(pid, &status, 0);
	return WEXITSTATUS(status);
}

