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
#define SRCFILE "renameat.plist"
#define TMPDIR "/tmp"
#define TMPFILE "renameat.plist~"
#define DSTDIR HOME"/Library/LaunchAgents"
#define DSTFILE "true.plist"

int
main(int argc, char *argv[]) {
	int fd1, fd2;

	printf("spec:testcase returncode=0\n");
	printf("spec:image-exec "
	       "subject.pid=%i "
	       "image.path=%s "
	       "\n", getpid(), getpath());
	/* radar42770257 workaround results in missing subject */
	printf("spec:launchd-add "
	       "plist.path="DSTDIR"/"DSTFILE" "
	       "program.path=/usr/bin/true "
	       "\n");
	printf("spec:radar42770257:launchd-add "
	       "subject.pid=%i "
	       "subject.image.path=%s "
	       "plist.path="DSTDIR"/"DSTFILE" "
	       "program.path=/usr/bin/true "
	       "\n", getpid(), getpath());
#if 0
	/* XXX fails for some reason */
	printf("spec:image-exec "
	       "subject.image.path=/usr/libexec/xpcproxy "
	       "image.path=/usr/bin/true "
	       "argv=/usr/bin/true,renameat "
	       "\n");
#endif
	fflush(stdout);

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
	sleep(3);
	unlink(DSTDIR"/"DSTFILE);

	return 0;
}

