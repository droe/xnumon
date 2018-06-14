#include <unistd.h>
#include <stdio.h>
#include <security/mac.h>

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
		__mac_execve("/usr/bin/true", cargv, NULL, NULL);
		perror("__mac_execve");
		return 1;
	}
	/* parent */
	printf("%i /usr/bin/true\n", pid);
	return 0;
}

