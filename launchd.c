/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2019, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

/*
 * Daemons and Services Programming Guide
 * https://developer.apple.com/library/content/documentation/MacOSX/Conceptual/BPSystemStartup
 *
 * TN2083: Daemons and Agents
 * https://developer.apple.com/library/content/technotes/tn2083/
 *
 * man launchd.plist
 *
 * http://www.launchd.info/
 */

#include "launchd.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/*
 * Documentation on the keys within this function was taken from the
 * launchd.plist manual page.
 */
int
launchd_plist_write(const char *label, const char *targetdir,
                    const char *execpath, int argc, char *argv[]) {
	char *plist;
	FILE *f;

	if (!targetdir)
		targetdir = "/Library/LaunchDaemons";
	if (asprintf(&plist, "%s/%s.plist", targetdir, label) == -1)
		return -1;

	(void)unlink(plist);
	f = fopen(plist, "w");
	free(plist);
	if (!f)
		return -1;
	fchmod(fileno(f), 0600);

	fprintf(f, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
	           "<!DOCTYPE plist PUBLIC"
	           " \"-//Apple Computer//DTD PLIST 1.0//EN\""
	           " \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
	           "<plist version=\"1.0\">\n"
	           "<dict>\n");

	/* This required key uniquely identifies the job to launchd. */
	fprintf(f, "\t<key>Label</key>\n"
	           "\t<string>%s</string>\n", label);

	/* This key maps to the first argument of execv(3) and indicates the
	 * absolute path to the executable for the job.  If this key is
	 * missing, then the first element of the array of strings provided to
	 * the ProgramArguments will be used instead.  This key is required in
	 * the absence of the ProgramArguments key. */
	fprintf(f, "\t<key>Program</key>\n"
	           "\t<string>%s</string>\n", execpath);

	/* This key maps to the second argument of execvp(3) and specifies the
	 * argument vector to be passed to the job when a process is spawned.
	 * This key is required in the absence of the Program key. */
	fprintf(f, "\t<key>ProgramArguments</key>\n"
	           "\t<array>\n");
	for (int i = 0; i < argc; i++) {
		fprintf(f, "\t\t<string>%s</string>\n", argv[i]);
	}
	fprintf(f, "\t</array>\n");

	/* This optional key is used to control whether your job is launched
	 * once at the time the job is loaded. The default is false. This key
	 * should be avoided, as speculative job launches have an adverse
	 * effect on system- boot and user-login scenarios. */
	fprintf(f, "\t<key>RunAtLoad</key>\n"
	           "\t<true/>\n");

	/* This optional key is used to control whether your job is to be kept
	 * continuously running or to let demand and conditions control the
	 * invocation.  The default is false and therefore only demand will
	 * start the job.  The value may be set to true to unconditionally keep
	 * the job alive. Alternatively, a dictionary of conditions may be
	 * specified to selectively control whether launchd keeps a job alive
	 * or not. If multiple keys are provided, launchd ORs them, thus
	 * providing maximum flexibility to the job to refine the logic and
	 * stall if necessary. If launchd finds no reason to restart the job,
	 * it falls back on demand based invocation.  Jobs that exit quickly
	 * and frequently when configured to be kept alive will be throttled to
	 * conserve system resources. */
	fprintf(f, "\t<key>KeepAlive</key>\n"
	           "\t<true/>\n");

	/* This key lets one override the default throttling policy imposed on
	 * jobs by launchd.  The value is in seconds, and by default, jobs will
	 * not be spawned more than once every 10 seconds.  The principle
	 * behind this is that jobs should linger around just in case they are
	 * needed again in the near future.  This not only reduces the latency
	 * of responses, but it encourages developers to amortize the cost of
	 * program invocation. */
	fprintf(f, "\t<key>ThrottleInterval</key>\n"
	           "\t<integer>60</integer>\n");

	/* The amount of time launchd waits between sending the SIGTERM signal
	 * and before sending a SIGKILL signal when the job is to be stopped.
	 * The default value is system-defined.  The value zero is interpreted
	 * as infinity and should not be used, as it can stall system shutdown
	 * forever. */
	fprintf(f, "\t<key>ExitTimeOut</key>\n"
	           "\t<integer>60</integer>\n");

	/* This optional key describes, at a high level, the intended purpose
	 * of the job.  The system will apply resource limits based on what
	 * kind of job it is.  If left unspecified, the system will apply light
	 * resource limits to the job, throttling its CPU usage and I/O
	 * bandwidth.  This classification is preferable to using the
	 * HardResourceLimits, SoftResourceLimits and Nice keys.
	 *
	 * Interactive jobs run with the same resource limitations as apps,
	 * that is to say, none. Interactive jobs are critical to maintaining a
	 * responsive user experience, and this key should only be used if an
	 * app's ability to be responsive depends on it, and cannot be made
	 * Adaptive. */
	fprintf(f, "\t<key>ProcessType</key>\n"
	           "\t<string>Interactive</string>\n");

#if 0
	/* This optional key specifies what nice(3) value should be applied to
	 * the daemon. */
	fprintf(f, "\t<key>Nice</key>\n"
	           "\t<integer>-5</integer>\n");
#endif

	/* Resource limits to be imposed on the job.  These adjust variables
	 * set with setrlimit(2).
	 *
	 *     Core <integer>
	 *     The largest size (in bytes) core file that may be created. */
#ifndef NDEBUG
	fprintf(f, "\t<key>SoftResourceLimits</key>\n"
	           "\t<dict><key>Core</key><integer>-1</integer></dict>\n");
	fprintf(f, "\t<key>HardResourceLimits</key>\n"
	           "\t<dict><key>Core</key><integer>-1</integer></dict>\n");
#endif

	/* This optional key is used to specify a directory to chdir(2) to
	 * before running the job. */
	fprintf(f, "\t<key>WorkingDirectory</key>\n"
	           "\t<string>/</string>\n");

#if 0
	/* This optional key specifies the user to run the job as.  This key is
	 * only applicable for services that are loaded into the privileged
	 * system domain. */
	fprintf(f, "\t<key>UserName</key>\n"
	           "\t<string>root</string>\n");

	/* This optional key specifies the group to run the job as.  This key
	 * is only applicable for services that are loaded into the privileged
	 * system domain.  If UserName is set and GroupName is not, then the
	 * group will be set to the primary group of the user. */
	fprintf(f, "\t<key>GroupName</key>\n"
	           "\t<string>admin</string>\n");

	/* This optional key specifies whether initgroups(3) to initialize the
	 * group list for the job.  The default is true.  This key will be
	 * ignored if the UserName key is not set.  Note that for agents, the
	 * UserName key is ignored. */
	fprintf(f, "\t<key>InitGroups</key>\n"
	           "\t<true/>\n");
#endif

#if 0
	/* This optional key specifies that the given path should be mapped to
	 * the job's stdout(4), and that any writes to the job's stdout(4) will
	 * go to the given file.  If the file does not exist, it will be created
	 * with writable permissions and ownership reflecting the user and/or
	 * group specified as the UserName and/or GroupName, respectively (if
	 * set) and permissions reflecting the umask(2) specified by the Umask
	 * key, if set. */
	fprintf(f, "\t<key>StandardOutPath</key>\n"
	           "\t<string>%s</string>\n", stdoutpath);
#endif

#if 0
	/* This optional key specifies that the given path should be mapped to
	 * the job's stderr(4), and that any writes to the job's stderr(4) will
	 * go to the given file.  Note that this file is opened as readable and
	 * writable as mandated by the POSIX specification for unclear reasons.
	 * If the file does not exist, it will be created with ownership
	 * reflecting the user and/or group specified as the UserName and/or
	 * GroupName, respectively (if set) and permissions reflecting the
	 * umask(2) specified by the Umask key, if set. */
	fprintf(f, "\t<key>StandardErrorPath</key>\n"
	           "\t<string>%s</string>\n", stderrpath);
#endif

	fprintf(f, "</dict>\n"
	           "</plist>\n");
	fclose(f);
	return 0;
}

