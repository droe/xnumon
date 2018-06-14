#include <unistd.h>
#include <stdio.h>

int
main(int argc, char *argv[]) {
	printf("%i\n", getpid());

	chdir("/tmp");

	return 0;
}

