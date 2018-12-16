/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include <unistd.h>
#include <stdio.h>

#if 0
#define __APPLE_API_PRIVATE
#include <security/mac.h>
#undef __APPLE_API_PRIVATE
#endif

#include "path.h"

#define PATH "/usr/bin/true"
#define ARGV0 "true"

/* <security/mac.h> was removed in High Sierra */
struct mac {
	size_t           m_buflen;
	char            *m_string;
};
typedef struct mac      *mac_t;
int __mac_execve(char *fname, char **argv, char **envv, mac_t _label);

int
main(int argc, char *argv[]) {
	pid_t pid;

	printf("spec:testcase returncode=0\n");
	fflush(stdout);

	pid = fork();
	if (pid == -1) {
		perror("fork");
		return 1;
	} else if (pid == 0) {
		/* child */
		char *cargv[2] = {ARGV0, 0};
		char *cenv[1] = {0};
		__mac_execve(PATH, cargv, cenv, NULL);
		perror("__mac_execve");
		return 1;
	}

	/* parent */
	printf("spec:image-exec "
	       "subject.pid=%i "
	       "subject.image.path=%s "
	       "image.path="PATH" "
	       "\n",
	       pid, getpath());
	printf("spec:radar42946744:image-exec "
	       "subject.pid=%i "
	       "subject.image.path=%s "
	       "image.path="PATH" "
	       "argv="ARGV0  /* __mac_execve() is missing argv and arge */
	       "\n",
	       pid, getpath());
	return 0;
}

