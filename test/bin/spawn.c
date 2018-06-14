#include <stdio.h>
#include <unistd.h>
#include <spawn.h>

int
main(int argc, char *argv[]) {
	int rv;
	pid_t pid;
	char *av[] = {"true", NULL};
	char *ev[] = {NULL};

	printf("%i\n", getpid());

	rv = posix_spawn(&pid, "/usr/bin/true", NULL, NULL, av, ev);
	if (rv == -1) {
		perror("spawn");
		return 1;
	}
	printf("%i /usr/bin/true\n", pid);
	return 0;
}

