#include <stdio.h>
#include <unistd.h>
#include <spawn.h>

int
main(int argc, char *argv[]) {
	int rv;
	char *av[] = {"true", NULL};
	char *ev[] = {NULL};

	printf("%i\n", getpid());

	rv = posix_spawn(NULL, "/usr/bin/true", NULL, NULL, av, ev);
	if (rv == -1) {
		perror("spawn");
		return 1;
	}
	printf("?? /usr/bin/true\n");
	return 0;
}

