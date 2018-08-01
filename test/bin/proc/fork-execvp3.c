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
		execvP("true", "/does-not-exist:/usr/bin:/bin", cargv);
		perror("execvP");
		return 1;
	}
	/* parent */
	printf("%i $MYPATH/true\n", pid);
	return 0;
}

