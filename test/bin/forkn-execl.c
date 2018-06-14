#include <unistd.h>
#include <stdio.h>

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
			return 0;
		}
		/* child 0..9 */
	}
	/* child 10 */
	printf("%i /usr/bin/true\n", getpid());
	execl("/usr/bin/true", "true", (char*)0);
	perror("exec");
	return 1;
}

