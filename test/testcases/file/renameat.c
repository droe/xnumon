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

#include "path.h"

#define TESTNAME "renameat"
#define SRCDIR TESTDIR"/testcases/file"
#define SRCFILE TESTNAME".plist"
#define TMPDIR "/tmp"
#define TMPFILE "ch.roe.xnumon.test."TESTNAME".plist~"
#define DSTDIR HOME"/Library/LaunchAgents"
#define DSTFILE "ch.roe.xnumon.test."TESTNAME".plist"

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
	printf("spec:radar42770257:launchd-add "
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

	system("launchctl unload \""DSTDIR"/"DSTFILE"\"");
	unlink(SRCDIR"/"SRCFILE);
	unlink(TMPDIR"/"TMPFILE);
	unlink(DSTDIR"/"DSTFILE);

	getplist();
	system("cp "SRCDIR"/"SRCFILE" "TMPDIR"/"TMPFILE);
	fd1 = open(TMPDIR, O_RDONLY);
	if (fd1 == -1) {
		perror("open("TMPDIR")");
		return 1;
	}
	fd2 = open(DSTDIR, O_RDONLY);
	if (fd2 == -1) {
		perror("open("DSTDIR")");
		return 1;
	}
	if (renameat(fd1, TMPFILE, fd2, DSTFILE) == -1) {
		perror("renameat");
		return 1;
	}
	close(fd2);
	close(fd1);
	system("launchctl load \""DSTDIR"/"DSTFILE"\"");
	sleep(1);

	system("launchctl unload \""DSTDIR"/"DSTFILE"\"");
	unlink(SRCDIR"/"SRCFILE);
	unlink(TMPDIR"/"TMPFILE);
	unlink(DSTDIR"/"DSTFILE);

	return 0;
}

