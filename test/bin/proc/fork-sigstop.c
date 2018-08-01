#include <unistd.h>
#include <stdio.h>
#include <signal.h>

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
		for (;;);
	}
	/* parent */
	printf("%i self\n", pid);
	kill(pid, SIGSTOP);
	sleep(1);
	kill(pid, SIGCONT);
	sleep(1);
	kill(pid, SIGTERM);
	return 0;
}

