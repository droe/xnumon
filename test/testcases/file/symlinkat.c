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

#define TESTNAME "symlinkat"
#define SRCDIR TESTDIR"/testcases/file"
#define SRCFILE TESTNAME".plist"
#define TMPDIR "/tmp"
#define TMPFILE "ch.roe.xnumon.test."TESTNAME".plist~"
#define DSTDIR HOME"/Library/LaunchAgents"
#define DSTFILE "ch.roe.xnumon.test."TESTNAME".plist"

int
main(int argc, char *argv[]) {
	int fd;

	printf("spec:testcase returncode=0\n");
	printf("spec:image-exec "
	       "subject.pid=%i "
	       "image.path=%s "
	       "\n", getpid(), getpath());
	/* write by any process */
	printf("spec:launchd-add "
	       "plist.path="DSTDIR"/"DSTFILE" "
	       "program.path=/usr/bin/true "
	       "program.argv=/usr/bin/true,"TESTNAME" "
	       "\n");
	/* misidentification of launchd as the source */
	printf("spec:absent:launchd-add "
	       "subject.pid=1 "
	       "plist.path="DSTDIR"/"DSTFILE" "
	       "program.path=/usr/bin/true "
	       "program.argv=/usr/bin/true,"TESTNAME" "
	       "\n");
	/* identification of the true subject */
	printf("spec:launchd-add "
	       "subject.pid=%i "
	       "subject.image.path=%s "
	       "plist.path="DSTDIR"/"DSTFILE" "
	       "program.path=/usr/bin/true "
	       "program.argv=/usr/bin/true,"TESTNAME" "
	       "\n", getpid(), getpath());
	/* launchd starting the agent */
	printf("spec:image-exec "
	       "subject.image.path=/usr/libexec/xpcproxy "
	       "image.path=/usr/bin/true "
	       "argv=/usr/bin/true,"TESTNAME" "
	       "\n");
	fflush(stdout);

	system("cp "SRCDIR"/"SRCFILE" "TMPDIR"/"TMPFILE);
	fd = open(DSTDIR, O_RDONLY);
	if (fd == -1) {
		perror("open("DSTDIR")");
		return 1;
	}
	if (symlinkat(TMPDIR"/"TMPFILE, fd, DSTFILE) == -1) {
		perror("symlinkat");
		return 1;
	}
	close(fd);
	system("launchctl load \""DSTDIR"/"DSTFILE"\"");
	sleep(1);
	system("launchctl unload \""DSTDIR"/"DSTFILE"\"");
	unlink(DSTDIR"/"DSTFILE);
	unlink(TMPDIR"/"TMPFILE);

	return 0;
}

