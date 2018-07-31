#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>

int
main(int argc, char *argv[]) {
	int fd;

	printf("%i\n", getpid());

	system("touch /tmp/test");
	fd = open("/tmp", O_RDONLY);
	if (fd == -1) {
		perror("open");
		return 1;
	}
	if (renameat(fd, "test", fd, "test2") == -1) {
		perror("renameat");
		return 1;
	}
	unlink("/tmp/test2");
	close(fd);

	return 0;
}

