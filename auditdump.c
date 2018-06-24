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
 * Test utility for easy access to customized auditpipe audit event feeds;
 * similar to piping /dev/auditpipe through praudit, but with configuration
 * of /dev/auditpipe in-kernel via the respective ioctl calls.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <bsm/libbsm.h>

#ifndef __BSD__
#include <getopt.h>
#endif /* !__BSD__ */

#include "aupipe.h"
#include "aupolicy.h"
#include "auclass.h"
#include "auevent.h"

static void
fusage(FILE *f, const char *argv0) {
	fprintf(f,
"Usage: %s [-dnrsxb] [-c classes]\n"
" -c classes     request only the comma-separated audit-classes: xnumon (xm),\n"
"                fread (fr), fwrite (fw), fattra (fa), fattrm (fm),\n"
"                fcreat (fc), fdelet (fd), fclose (cl), proc (pc), net (nt),\n"
"                ipc (ip), na, login (lo), auth (au), app (ap), ioctl (io),\n"
"                exec (ex), misc (ot), file (fr,fw,fa,fm,fc,fd,cl), all\n"
" -C             clear custom classes on exit (system-globally!)\n"
" -d del         use delimiter del instead of comma for separating tokens\n"
" -n             do not resolve user and group names\n"
" -r             output raw numerical format\n"
" -s             output short format\n"
" -x             output XML format\n"
" -b             output binary format for piping into auditreduce|praudit\n"
, argv0);
}

static int active = 1;

void
handle_sig(UNUSED int signum) {
	active = 0;
}

int
main(int argc, char *argv[]) {
	FILE *f;
	int ch, rv;
	char del[2] = {',', 0};
	int binary = 0;
	int oflags = AU_OFLAG_NONE;
	unsigned int classmask = AC_ALL;
	int clearmask = 0;
	const char *argv0 = argv[0];

	while ((ch = getopt(argc, argv, "c:Cd:hnrsxb")) != -1) {
		switch (ch) {
			case 'b':
				binary = 1;
				break;
			case 'c':
				classmask = auclass_maskparse(optarg);
				break;
			case 'C':
				clearmask = 1;
				break;
			case 'd':
				del[0] = optarg[0];
				break;
			case 'h':
				fusage(stdout, argv0);
				exit(EXIT_SUCCESS);
			case 'n':
				oflags |= AU_OFLAG_NORESOLVE;
				break;
			case 'r':
				oflags |= AU_OFLAG_RAW;
				break;
			case 's':
				oflags |= AU_OFLAG_SHORT;
				break;
			case 'x':
				oflags |= AU_OFLAG_XML;
				break;
			case '?':
				exit(EXIT_FAILURE);
			default:
				fusage(stderr, argv0);
				exit(EXIT_FAILURE);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc > 0) {
		fusage(stderr, argv0);
		exit(EXIT_FAILURE);
	}

	if (classmask == AC_NONE) {
		fprintf(stderr, "%s: invalid classmask\n", argv0);
		exit(EXIT_FAILURE);
	}

	signal(SIGINT, handle_sig);
	signal(SIGQUIT, handle_sig);
	signal(SIGTERM, handle_sig);

	if (classmask & AC_XNUMON) {
		if (auclass_addmask(AC_XNUMON,
		                    auclass_xnumon_events_procmon) == -1 ||
		    auclass_addmask(AC_XNUMON,
		                    auclass_xnumon_events_hackmon) == -1 ||
		    auclass_addmask(AC_XNUMON,
		                    auclass_xnumon_events_filemon) == -1) {
			fprintf(stderr, "%s: addmask(AC_XNUMON) failed\n",
			                argv0);
			exit(EXIT_FAILURE);
		}
	}

	if (aupolicy_ensure(AUDIT_ARGV|AUDIT_ARGE) == -1) {
		fprintf(stderr, "Failed to configure audit policy\n");
		exit(EXIT_FAILURE);
	}

	if ((f = aupipe_fopen(classmask)) == NULL) {
		exit(EXIT_FAILURE);
	}

	while (active) {
		int reclen;
		u_char *recbuf;
		tokenstr_t tok;

		reclen = au_read_rec(f, &recbuf);
		if (reclen == -1) {
			fprintf(stderr, "au_read_rec(): %s (%i)\n",
			        strerror(errno), errno);
			exit(EXIT_FAILURE);
		}
		if (reclen == 0) {
			free(recbuf);
			fprintf(stderr, "sleeping\n");
			sleep(1);
			continue;
		}

		if (binary) {
			fwrite(recbuf, reclen, 1, stdout);
			fflush(stdout);
			free(recbuf);
			continue;
		}

		for (int recpos = 0; recpos < reclen;) {
			rv = au_fetch_tok(&tok, recbuf+recpos, reclen-recpos);
			if (rv == -1) {
				fprintf(stderr, "au_fetch_tok() error,"
				                " skipping record\n");
				break;
			}
			au_print_flags_tok(stdout, &tok, del, oflags);
			printf("\n");
			recpos += tok.len;
		}

		free(recbuf);
	}

	if (clearmask) {
		if (auclass_removemask(AC_XNUMON,
		                       auclass_xnumon_events_procmon) == -1 ||
		    auclass_removemask(AC_XNUMON,
		                       auclass_xnumon_events_hackmon) == -1 ||
		    auclass_removemask(AC_XNUMON,
		                       auclass_xnumon_events_filemon) == -1) {
			fprintf(stderr, "%s: removemask(AC_XNUMON) failed\n",
			                argv0);
			exit(EXIT_FAILURE);
		}
	}

	fclose(f);
	exit(EXIT_SUCCESS);
}

