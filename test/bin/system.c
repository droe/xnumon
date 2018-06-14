#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int
main(int argc, char *argv[]) {
	int rv;

	printf("%i\n", getpid());

	rv = system("/usr/bin/true");
	if (rv == -1) {
		perror("system");
		return 1;
	}
	printf("?? /usr/bin/true\n");
	return 0;
}

