#include <stdio.h>
#include <unistd.h>
#include <spawn.h>

#include "getpath.h"

#define PATH "/usr/bin/true"
#define ARGV0 "true.NOPID"

int
main(int argc, char *argv[]) {
	int rv;
	char *av[] = {ARGV0, NULL};
	char *ev[] = {NULL};

	rv = posix_spawn(NULL, PATH, NULL, NULL, av, ev);
	if (rv == -1) {
		perror("spawn");
		return 1;
	}

	printf("spec:image-exec "
	       "subject.image.path=%s "
	       "image.path="PATH" "
	       "argv="ARGV0
	       "\n", getpath());

	return 0;
}

