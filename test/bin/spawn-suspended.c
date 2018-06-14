#include <stdio.h>
#include <unistd.h>
#include <spawn.h>
#include <signal.h>
#include <errno.h>

int
main(int argc, char *argv[]) {
	int rv;
	pid_t pid;
	char *av[] = {"true", NULL};
	char *ev[] = {NULL};
	posix_spawnattr_t attr;

	printf("%i\n", getpid());

	rv = posix_spawnattr_init(&attr);
	if (rv != 0) {
		errno = rv;
		perror("posix_spawnattr_init");
	}
	rv = posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);
	if (rv != 0) {
		errno = rv;
		perror("posix_spawnattr_setflags");
	}
	rv = posix_spawn(&pid, "/usr/bin/true", NULL, NULL, av, ev);
	if (rv == -1) {
		perror("spawn");
		return 1;
	}
	printf("%i /usr/bin/true\n", pid);

	kill(pid, SIGCONT);

	return 0;
}

