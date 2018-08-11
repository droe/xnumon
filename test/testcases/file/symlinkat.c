/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

/*
 * Because the destination file is outside of the paths that we are monitoring,
 * the missed AUE_SYMLINKAT due to unresolved paths will not be compensated
 * later, because the resolved paths in AUE_CLOSE point to outside of the
 * monitored paths.  Currently xnumon cannot handle that yet.
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>

#include "getpath.h"

#define TESTNAME "symlinkat"
#define SRCDIR TESTDIR"/testcases/file"
#define SRCFILE TESTNAME".plist"
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
	printf("spec:radar42784847:launchd-add "
	       "plist.path="DSTDIR"/"DSTFILE" "
	       "program.path=/usr/bin/true "
	       "program.argv=/usr/bin/true,%i "
	       "\n", getpid());
	/* misidentification of launchd as the source */
	printf("spec:absent:launchd-add "
	       "subject.pid=1 "
	       "plist.path="DSTDIR"/"DSTFILE" "
	       "program.path=/usr/bin/true "
	       "program.argv=/usr/bin/true,%i "
	       "\n", getpid());
	/* identification of the true subject */
	printf("spec:radar42784847:launchd-add "
	       "subject.pid=%i "
	       "subject.image.path=%s "
	       "plist.path="DSTDIR"/"DSTFILE" "
	       "program.path=/usr/bin/true "
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
	fd = open(DSTDIR, O_RDONLY);
	if (fd == -1) {
		perror("open("DSTDIR")");
		return 1;
	}
	if (symlinkat(SRCDIR"/"SRCFILE, fd, DSTFILE) == -1) {
		perror("symlinkat");
		return 1;
	}
	close(fd);
	sleep(1);
	system("launchctl unload \""DSTDIR"/"DSTFILE"\"");
	system("launchctl load -F \""DSTDIR"/"DSTFILE"\"");
	sleep(1);
	system("launchctl unload \""DSTDIR"/"DSTFILE"\"");
	unlink(DSTDIR"/"DSTFILE);

	return 0;
}

