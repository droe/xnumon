/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include "cf.h"

#include "aev.h"

#include <stdlib.h>
#include <strings.h>

char *
cf_cstr(CFStringRef str) {
	if (!str)
		return NULL;

	/* try quick direct access */
	const char *p = CFStringGetCStringPtr(str, kCFStringEncodingUTF8);
	if (p) {
		return strdup(p);
	}

	/* do copyout */
	CFIndex len = CFStringGetLength(str);
	CFIndex bufsz = CFStringGetMaximumSizeForEncoding(
	                        len, kCFStringEncodingUTF8) + 1;
	char *buf = (char *)malloc(bufsz);
	if (!buf)
		return NULL;
	if (CFStringGetCString(str, buf, bufsz, kCFStringEncodingUTF8))
		return buf;
	free(buf);
	return NULL;
}

/*
 * Allocated array of separately allocated c strings; caller needs to keep
 * track of the number of strings in the array by separate means.
 */
char **
cf_cstrv(CFArrayRef arr) {
	size_t tmpvc;
	char **tmpv;

	if (!arr)
		return NULL;

	tmpvc = CFArrayGetCount(arr);
	tmpv = malloc(tmpvc * sizeof(char *));
	if (!tmpv)
		return NULL;
	bzero(tmpv, tmpvc * sizeof(char *));
	for (size_t i = 0; i < tmpvc; i++) {
		CFStringRef s = (CFStringRef)CFArrayGetValueAtIndex(arr, i);
		tmpv[i] = cf_cstr(s);
		if (!tmpv[i])
			goto errout;
	}
	return tmpv;
errout:
	for (size_t i = 0; i < tmpvc; i++) {
		if (tmpv[i])
			free(tmpv[i]);
	}
	free(tmpv);
	return NULL;
}

/*
 * Compact aev representation of an array of strings within a single minimal
 * memory allocation; initial pointer array is NULL-terminated.
 *
 * This is not the most efficient way to do it, but given that we don't know
 * the effective length of each string before copying it out, there is no good
 * alternative.
 */
char **
cf_aev(CFArrayRef arr) {
	size_t tmpvc;
	char **tmpv, **v = NULL;

	if (!arr)
		return NULL;

	tmpvc = CFArrayGetCount(arr);
	tmpv = malloc(tmpvc * sizeof(char *));
	if (!tmpv)
		return NULL;
	bzero(tmpv, tmpvc * sizeof(char *));
	for (size_t i = 0; i < tmpvc; i++) {
		CFStringRef s = (CFStringRef)CFArrayGetValueAtIndex(arr, i);
		tmpv[i] = cf_cstr(s);
		if (!tmpv[i])
			goto errout;
	}
	v = aev_new(tmpvc, tmpv);
errout:
	for (size_t i = 0; i < tmpvc; i++) {
		if (tmpv[i])
			free(tmpv[i]);
	}
	free(tmpv);
	return v;
}

CFURLRef
cf_url(const char *cpath) {
	CFStringRef path;
	CFURLRef url;

	path = CFStringCreateWithCString(kCFAllocatorDefault,
	                                 cpath,
	                                 kCFStringEncodingUTF8);
	if (!path)
		return NULL;
	url = CFURLCreateWithFileSystemPath(kCFAllocatorDefault,
	                                    path,
	                                    kCFURLPOSIXPathStyle,
	                                    true);
	CFRelease(path);
	return url;
}

/*
 * FIXME CFURLCreateDataAndPropertiesFromResource() is deprecated and should
 * be replaced by the more convoluted CFURLCopyResourcePropertiesForKeys().
 */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

CFPropertyListRef
cf_plist_load(const char *path) {
	CFURLRef url;
	CFDataRef data;
	CFPropertyListRef plist;
	CFErrorRef error = NULL;
	SInt32 errcode;
	Boolean ok;

	if (!path)
		return NULL;

	url = cf_url(path);
	if (!url)
		return NULL;

	data = NULL;
	ok = CFURLCreateDataAndPropertiesFromResource(kCFAllocatorDefault,
	                                              url,
	                                              &data,
	                                              NULL,
	                                              NULL,
	                                              &errcode);
	CFRelease(url);
	if (!ok)
		return NULL;

	plist = CFPropertyListCreateWithData(kCFAllocatorDefault,
	                                     data,
	                                     kCFPropertyListImmutable,
	                                     NULL,
	                                     &error);
	CFRelease(data);
	if (error)
		CFRelease(error);
	if (!plist)
		return NULL;

	if (CFGetTypeID(plist) != CFDictionaryGetTypeID()) {
		CFRelease(plist);
		return NULL;
	}
	return plist;
}

