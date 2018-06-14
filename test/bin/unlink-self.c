#include <unistd.h>
#include <stdio.h>

int
main(int argc, char *argv[]) {
	printf("%i\n", getpid());

	if (unlink(argv[0]) == -1) {
		perror("unlink");
		return 1;
	}

	return 0;
}

