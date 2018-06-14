#include <unistd.h>
#include <stdio.h>
#include <spawn.h>
#include <errno.h>

int
main(int argc, char *argv[]) {
	int rv;
	pid_t pid;
	posix_spawnattr_t attr;
	char *av[] = {"true", NULL};
	char *ev[] = {NULL};

	printf("%i\n", getpid());

	pid = fork();
	if (pid == -1) {
		perror("fork");
		return 1;
	} else if (pid == 0) {
		/* child */
		rv = posix_spawnattr_init(&attr);
		if (rv != 0) {
			errno = rv;
			perror("posix_spawnattr_init");
		}
		rv = posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETEXEC);
		if (rv != 0) {
			errno = rv;
			perror("posix_spawnattr_setflags");
		}
		rv = posix_spawn(NULL, "/usr/bin/true", NULL, &attr, av, ev);
		perror("spawn");
		return 1;
	}
	/* parent */
	printf("%i /usr/bin/true\n", pid);
	return 0;
}

