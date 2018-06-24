/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include "config.h"
#include "evtloop.h"
#include "sys.h"
#include "log.h"
#include "kextctl.h"
#include "build.h"
#include "policy.h"
#include "auclass.h"
#include "aupolicy.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#ifndef __BSD__
#include <getopt.h>
#endif /* !__BSD__ */

/*
 * Use of a pidfile is enforced in order to avoid nasty feedback loops
 * between multiple instances of xnumon running in parallel (e.g. AUE_CLOSE).
 */
#define XNUMON_PIDFILE "/var/run/xnumon.pid"

#define OPTSTRING "o:l:f:1mdc:Vh"

static void
fusage(FILE *f, const char *argv0) {
	fprintf(f,
"Usage: %s [-d] [-c cfgfile] [-olf1mVh]\n"
" -d             launchd mode: adapt behaviour to launchd expectations\n"
" -c cfgfile     load configuration plist from cfgfile instead of from\n"
"                /Library/Application Support/ch.roe.xnumon/\n"
"\n"
" -o key=value   override configuration key of type string with value\n"
" -l logfmt      use log format: json*, yaml\n"
" -f logdst      use log destination: file, stdout*, syslog\n"
" -1             use compact one-line log format (not compatible w/yaml)\n"
" -m             use multi-line log format (not compatible w/syslog)\n"
"\n"
" -V             print version and build information and exit\n"
, argv0);
}

static void
fversion(FILE *f) {
	fprintf(f, "%s %s (built %s)\n",
	           build_pkgname, build_version, build_date);
	fprintf(f, "Copyright (c) 2017-2018, "
	           "Daniel Roethlisberger <daniel@roe.ch>\n");
	fprintf(f, "https://www.roe.ch/xnumon\n");
	fprintf(f, "Build info: %s\n", build_info);

	kextctl_version(f);
	log_version(f);
}

int
main(int argc, char *argv[]) {
	int ch, rv;
	char *cfgpath = NULL;
	config_t *cfg;
	int pidfd = -1;
	char *p;

	while ((ch = getopt(argc, argv, OPTSTRING)) != -1) {
		switch (ch) {
		/* handled in second pass */
		case 'o':
		case 'l':
		case 'f':
		case '1':
		case 'm':
		case 'd':
			break;
		/* handled in first pass */
		case 'c':
			cfgpath = strdup(optarg);
			if (!cfgpath) {
				fprintf(stderr, "Out of memory!\n");
				exit(EXIT_FAILURE);
			}
			break;
		case 'V':
			fversion(stdout);
			exit(EXIT_SUCCESS);
			break;
		case 'h':
			fusage(stdout, argv[0]);
			exit(EXIT_SUCCESS);
		case '?':
			exit(EXIT_FAILURE);
		default:
			fusage(stderr, argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	optreset = 1;
	optind = 1;

	fversion(stderr);
	umask(0027);

	fprintf(stderr, "Loading configuration:\n");
	cfg = config_new(cfgpath);
	if (cfgpath)
		free(cfgpath);
	if (!cfg) {
		fprintf(stderr, "Failed to load configuration!\n");
		exit(EXIT_FAILURE);
	}
	fprintf(stderr, "Loaded '%s'\n", cfg->path);

	while ((ch = getopt(argc, argv, OPTSTRING)) != -1) {
		switch (ch) {
		/* handled in second pass */
		case 'o':
			p = optarg;
			while ((*p) && (*p != '='))
				p++;
			if (*p != '=') {
				fprintf(stderr, "Option -o missing value\n");
				exit(EXIT_FAILURE);
			}
			*p = '\0';
			p++;
			if (config_str(cfg, optarg, p) == -1) {
				fprintf(stderr, "Option -o invalid value\n");
				exit(EXIT_FAILURE);
			}
			break;
		case 'l':
			if (config_str(cfg, "log_format", optarg) == -1) {
				fprintf(stderr, "Option -l invalid fmt '%s'\n",
				                optarg);
				exit(EXIT_FAILURE);
			}
			break;
		case 'f':
			if (config_str(cfg, "log_destination", optarg) == -1) {
				fprintf(stderr, "Option -f invalid dst '%s'\n",
				                optarg);
				exit(EXIT_FAILURE);
			}
			break;
		case '1':
			if (config_str(cfg, "log_mode", "oneline") == -1) {
				fprintf(stderr, "Option -1 internal error\n");
				exit(EXIT_FAILURE);
			}
			break;
		case 'm':
			if (config_str(cfg, "log_mode", "multiline") == -1) {
				fprintf(stderr, "Option -m internal error\n");
				exit(EXIT_FAILURE);
			}
			break;
		case 'd':
			cfg->launchd_mode = true;
			break;
		/* handled in first pass */
		case 'c':
		case 'V':
		case 'h':
		case '?':
		default:
			break;
		}
	}
	fprintf(stderr, "Loaded configuration overrides from command line\n");

	if (argc > optind) {
		fusage(stderr, argv[0]);
		rv = -1;
		goto errout;
	}

	argc -= optind;
	argv += optind;

	if (getuid() && (setuid(0) == -1)) {
		fprintf(stderr, "Must be run with root privileges\n");
		rv = -1;
		goto errout;
	}

	if (aupolicy_ensure(AUDIT_ARGV/*|AUDIT_ARGE*/) == -1) {
		fprintf(stderr, "Failed to configure audit policy\n");
		rv = -1;
		goto errout;
	}

	if (auclass_addmask(AC_XNUMON, auclass_xnumon_events_procmon) == -1) {
		fprintf(stderr, "Failed to configure AC_XNUMON class mask\n");
		rv = -1;
		goto errout;
	}
	if (LOGEVT_WANT(cfg->events, LOGEVT_HACKMON) &&
	    auclass_addmask(AC_XNUMON, auclass_xnumon_events_hackmon) == -1) {
		fprintf(stderr, "Failed to configure AC_XNUMON class mask\n");
		rv = -1;
		goto errout;
	}
	if (LOGEVT_WANT(cfg->events, LOGEVT_FILEMON) &&
	    auclass_addmask(AC_XNUMON, auclass_xnumon_events_filemon) == -1) {
		fprintf(stderr, "Failed to configure AC_XNUMON class mask\n");
		rv = -1;
		goto errout;
	}

	if (policy_task_sched_priority() == -1) {
		fprintf(stderr, "Failed to set task sched priority\n");
		rv = -1;
		goto errout;
	}

#if 0	/* terra pericolosa */
	if (policy_thread_sched_priority(TP_HIGH) == -1) {
		fprintf(stderr, "Failed to set main thread sched priority\n");
		rv = -1;
		goto errout;
	}
#endif

	if (policy_thread_diskio_important() == -1) {
		fprintf(stderr, "Failed to set main thread diskio policy\n");
		rv = -1;
		goto errout;
	}

	if (sys_limit_nofile(cfg->limit_nofile) == -1) {
		fprintf(stderr, "Failed to limit open files to %zu\n",
		        cfg->limit_nofile);
		rv = -1;
		goto errout;
	}

	pidfd = sys_pidf_open(XNUMON_PIDFILE);
	if (pidfd == -1) {
		fprintf(stderr, "Failed to open pidfile%s\n",
		                (errno == EWOULDBLOCK) ?
		                " - already running?" : "");
		rv = -1;
		goto errout;
	}
	if (sys_pidf_write(pidfd) == -1) {
		fprintf(stderr, "Failed to write pidfile\n");
		rv = -1;
		goto errout;
	}

	rv = evtloop_run(cfg);
	if (rv == -1) {
		fprintf(stderr, "Event loop returned error\n");
	}
	/* this is system-global, only run this if holding pidfile */
	if (auclass_removemask(AC_XNUMON,
	                       auclass_xnumon_events_procmon) == -1 ||
	    auclass_removemask(AC_XNUMON,
	                       auclass_xnumon_events_hackmon) == -1 ||
	    auclass_removemask(AC_XNUMON,
	                       auclass_xnumon_events_filemon) == -1) {
		fprintf(stderr, "Failed to configure AC_XNUMON class mask\n");
	}
errout:
	if (pidfd != -1)
		sys_pidf_close(pidfd, XNUMON_PIDFILE);
	if (cfg)
		config_free(cfg);
	if (rv == -1) {
		fprintf(stderr, "Fatal error, exiting\n");
		exit(EXIT_FAILURE);
	}
	exit(EXIT_SUCCESS);
}


