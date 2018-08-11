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
 * This code was written for use in short-living test case executables and is
 * utterly unfit for any other purposes.
 */

#ifndef TEST_GETPATH_H
#define TEST_GETPATH_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <mach-o/dyld.h>

static inline const char *
getpath(void) {
	char pathbuf[1024];
	uint32_t size = sizeof(pathbuf);
	if (_NSGetExecutablePath(pathbuf, &size) != 0)
		return NULL;
	return realpath(pathbuf, NULL);
}


static const char header[] =
	"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
	"<!DOCTYPE plist PUBLIC -//Apple Computer//DTD PLIST 1.0//EN "
	"http://www.apple.com/DTDs/PropertyList-1.0.dtd>\n"
	"<plist version=\"1.0\">\n"
	"\t<dict>\n"
	"\t\t<key>Label</key>\n"
	"\t\t<string>ch.roe.xnumon.test.";
static const char body[] =
	"</string>\n"
	"\t\t<key>ProgramArguments</key>\n"
	"\t\t<array>\n"
	"\t\t\t<string>/usr/bin/true</string>\n"
	"\t\t\t<string>";
static const char footer[] =
	"</string>\n"
	"\t\t</array>\n"
	"\t\t<key>RunAtLoad</key>\n"
	"\t\t<true/>\n"
	"\t</dict>\n"
	"</plist>\n";

static inline const char *
getplist(void) {
	char pathbuf[1024];
	uint32_t size = sizeof(pathbuf) - 2;
	if (_NSGetExecutablePath(pathbuf, &size) != 0)
		return NULL;
	memcpy(&pathbuf[strlen(pathbuf)-4], "plist", 6);

	FILE *f = fopen(pathbuf, "w");
	fprintf(f, "%s%i%s%i%s", header, getpid(), body, getpid(), footer);
	fclose(f);

	return realpath(pathbuf, NULL);
}

#endif
