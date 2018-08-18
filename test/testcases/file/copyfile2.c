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
 * Note that this uses copyfile(2), not copyfile(3) from libc.
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/syscall.h>

#include "getpath.h"

#define TESTNAME "copyfile2"
#define SRCDIR TESTDIR"/testcases/file"
#define SRCFILE TESTNAME".plist"
#define DSTDIR HOME"/Library/LaunchAgents"
#define DSTFILE "ch.roe.xnumon.test."TESTNAME".plist"

int
main(int argc, char *argv[]) {
	/* hfs and hfs+ do not support copyfile(2), ensure failure */
	printf("spec:testcase returncode=1\n");
	printf("spec:image-exec "
	       "subject.pid=%i "
	       "image.path=%s "
	       "\n", getpid(), getpath());
	printf("spec:absent:launchd-add "
	       "plist.path="DSTDIR"/"DSTFILE" "
	       "program.rpath=/usr/bin/true "
	       "program.argv=/usr/bin/true,%i "
	       "\n", getpid());
#if 0
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
#endif

	getplist();
	if (syscall(SYS_copyfile, SRCDIR"/"SRCFILE, DSTDIR"/"DSTFILE, 0777,
	            CPF_OVERWRITE) < 0) {
		perror("copyfile(2)");
		return 1;
	}
	/* not reached unless copyfile(2) is supported by the file system */

#if 0
	system("launchctl load \""DSTDIR"/"DSTFILE"\"");
	sleep(1);
	system("launchctl unload \""DSTDIR"/"DSTFILE"\"");
#endif
	unlink(DSTDIR"/"DSTFILE);

	return 0;
}

