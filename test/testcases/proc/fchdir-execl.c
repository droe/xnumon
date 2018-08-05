#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

#define PATH "/usr/bin/true"
#define ARGV0 "true"
#define CWD "/tmp"

int
main(int argc, char *argv[]) {
	char *cwd = realpath(CWD, NULL);
	int fd;

	printf("spec:image-exec "
	       "subject.pid=%i "
	       "image.path="PATH" "
	       "argv="ARGV0" "
	       "cwd=%s\n",
	       getpid(), cwd);
	fflush(stdout);

	fd = open(CWD, O_RDONLY);
	if (fd == -1) {
		perror("open");
		return 1;
	}
	if (fchdir(fd) == -1) {
		perror("fchdir");
		return 1;
	}
	close(fd);

	execl(PATH, ARGV0, (char*)0);
	perror("exec");

	return 0;
}

