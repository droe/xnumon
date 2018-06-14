#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int
main(int argc, char *argv[]) {
	char buf[1024*16];
	int fd;

	printf("%i\n", getpid());

	fd = open(argv[0], O_RDWR);
	if (fd == -1) {
		perror("open");
		return 1;
	}
	bzero(buf, sizeof(buf));
	if (pwrite(fd, buf, sizeof(buf), 0) == -1) {
		perror("write");
		return 1;
	}
	close(fd);

	return 0;
}

