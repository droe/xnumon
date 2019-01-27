/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2019, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include "os.h"

#include "cf.h"

#include <stdio.h>
#include <stdlib.h>

#include <CoreFoundation/CoreFoundation.h>

#define SYSVER_PLIST "/System/Library/CoreServices/SystemVersion.plist"

static char *os_nam_s = NULL;
static char *os_ver_s = NULL;
static char *os_bui_s = NULL;

int
os_init(void) {
	CFPropertyListRef plist;

	plist = cf_plist_load(SYSVER_PLIST);
	if (!plist)
		return -1;

	if (os_nam_s)
		free(os_nam_s);
	if (os_ver_s)
		free(os_ver_s);
	if (os_bui_s)
		free(os_bui_s);
	os_nam_s = cf_cstr(CFDictionaryGetValue((CFDictionaryRef)plist,
	                                        CFSTR("ProductName")));
	os_ver_s = cf_cstr(CFDictionaryGetValue((CFDictionaryRef)plist,
	                                        CFSTR("ProductVersion")));
	os_bui_s = cf_cstr(CFDictionaryGetValue((CFDictionaryRef)plist,
	                                        CFSTR("ProductBuildVersion")));
	CFRelease(plist);
	return (os_nam_s && os_ver_s && os_bui_s) ? 0 : -1;
}

void
os_fini(void) {
	if (os_nam_s) {
		free(os_nam_s);
		os_nam_s = NULL;
	}
	if (os_ver_s) {
		free(os_ver_s);
		os_ver_s = NULL;
	}
	if (os_bui_s) {
		free(os_bui_s);
		os_bui_s = NULL;
	}
}

const char *
os_name(void) {
	return os_nam_s;
}

const char *
os_version(void) {
	return os_ver_s;
}

const char *
os_build(void) {
	return os_bui_s;
}

