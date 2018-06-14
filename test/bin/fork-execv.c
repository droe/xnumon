#include <unistd.h>
#include <stdio.h>

int
main(int argc, char *argv[]) {
	pid_t pid;

	printf("%i\n", getpid());

	pid = fork();
	if (pid == -1) {
		perror("fork");
		return 1;
	} else if (pid == 0) {
		/* child */
		char *cargv[2] = {"true", 0};
		execv("/usr/bin/true", cargv);
		perror("execv");
		return 1;
	}
	/* parent */
	printf("%i /usr/bin/true\n", pid);
	return 0;
}

