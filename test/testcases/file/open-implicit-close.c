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
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>

#include "getpath.h"

#define SRCDIR TESTDIR"/testcases/file"
#define SRCFILE "open-implicit-close.plist"
#define DSTDIR HOME"/Library/LaunchAgents"
#define DSTFILE "ch.roe.xnumon.test.open-implicit-close.plist"

int
main(int argc, char *argv[]) {
	int fd1, fd2;

	printf("spec:testcase returncode=0\n");
	printf("spec:image-exec "
	       "subject.pid=%i "
	       "image.path=%s "
	       "\n", getpid(), getpath());
	/* write by any process */
	printf("spec:launchd-add "
	       "plist.path="DSTDIR"/"DSTFILE" "
	       "program.rpath=/usr/bin/true "
	       "program.argv=/usr/bin/true,%i "
	       "\n", getpid());
	/* misidentification of launchd as the source */
	printf("spec:absent:launchd-add "
	       "subject.pid=1 "
	       "plist.path="DSTDIR"/"DSTFILE" "
	       "program.rpath=/usr/bin/true "
	       "program.argv=/usr/bin/true,%i "
	       "\n", getpid());
	/* identification of the true subject */
	printf("spec:launchd-add "
	       "subject.pid=%i "
	       "subject.image.path=%s "
	       "plist.path="DSTDIR"/"DSTFILE" "
	       "program.rpath=/usr/bin/true "
	       "program.argv=/usr/bin/true,%i "
	       "\n", getpid(), getpath(), getpid());
	/* launchd starting the agent */
	printf("spec:image-exec "
	       "subject.image.path=/usr/libexec/xpcproxy "
	       "image.path=/usr/bin/true "
	       "argv=/usr/bin/true,%i "
	       "\n", getpid());
	fflush(stdout);

	getplist();
	fd1 = open(SRCDIR"/"SRCFILE, O_RDONLY);
	if (fd1 == -1) {
		perror("open("SRCDIR"/"SRCFILE")");
		return 1;
	}
	fd2 = open(DSTDIR"/"DSTFILE, O_RDWR|O_CREAT, 0777);
	if (fd2 == -1) {
		perror("open("DSTDIR"/"DSTFILE")");
		return 1;
	}

	char buf[2048];
	ssize_t n;
	n = read(fd1, buf, sizeof(buf));
	if (n < 0) {
		perror("read");
		return 1;
	}
	if (n == 0) {
		return 1;
	}
	n = write(fd2, buf, n);
	if (n < 0) {
		perror("write");
		return 1;
	}

	/* close(fd2); */
	close(fd1);

	if (fork() == 0 && fork() == 0) {
		sleep(1);
		system("launchctl load \""DSTDIR"/"DSTFILE"\"");
		sleep(1);
		system("launchctl unload \""DSTDIR"/"DSTFILE"\"");
		unlink(DSTDIR"/"DSTFILE);
		return 0;
	}

	return 0;
}

