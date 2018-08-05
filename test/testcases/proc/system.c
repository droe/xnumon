#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "getpath.h"

#define PATH "/usr/bin/true"

int
main(int argc, char *argv[]) {
	int rv;

	rv = system(PATH);
	if (rv == -1) {
		perror("system");
		return 1;
	}

	printf("spec:image-exec "
	       "subject.image.path=%s "
	       "image.path=/bin/sh "
	       "\n", getpath());

	printf("spec:image-exec "
	       "subject.image.path=/bin/sh "
	       "image.path="PATH" "
	       "argv="PATH
	       "\n");

	return rv;
}

