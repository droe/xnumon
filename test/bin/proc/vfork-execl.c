#include <unistd.h>
#include <stdio.h>

int
main(int argc, char *argv[]) {
	pid_t pid;

	printf("%i\n", getpid());

	pid = vfork();
	if (pid == -1) {
		perror("vfork");
		return 1;
	} else if (pid == 0) {
		/* child */
		execl("/usr/bin/true", "true", (char*)0);
		perror("exec");
		_exit(1);
	}
	/* parent */
	printf("%i /usr/bin/true\n", pid);
	return 0;
}

