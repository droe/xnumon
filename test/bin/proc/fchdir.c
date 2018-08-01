#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>

int
main(int argc, char *argv[]) {
	int fd;

	printf("%i\n", getpid());

	fd = open("/tmp", O_RDONLY);
	if (fd == -1) {
		perror("open");
		return 1;
	}
	if (fchdir(fd) == -1) {
		perror("fchdir");
		return 1;
	}
	close(fd);

	return 0;
}

