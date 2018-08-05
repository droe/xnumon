#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int
main(int argc, char *argv[]) {
	int fd;

	printf("%i\n", getpid());

	fd = open("/tmp/implicit_close", O_RDWR|O_CREAT, 0777);
	if (fd == -1) {
		perror("open");
		return 1;
	}

	/* close(fd); */

	return 0;
}

