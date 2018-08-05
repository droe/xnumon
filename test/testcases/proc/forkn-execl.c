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

	for (int i = 0; i < 10; i++) {
		printf("%i\n", getpid());
		pid = fork();
		if (pid == -1) {
			perror("fork");
			return 1;
		} else if (pid != 0) {
			/* parent */
			int status;
			waitpid(pid, &status, 0);
			return WEXITSTATUS(status);
		}
		/* child 0..9 */
	}
	/* child 10 */
	printf("spec:image-exec "
	       "subject.pid=%i "
	       "subject.image.path=%s "
	       "image.path="PATH" "
	       "argv="ARGV0
	       "\n",
	       getpid(), getpath());
	fflush(stdout);

	execl(PATH, ARGV0, (char*)0);
	perror("exec");
	return 1;
}

