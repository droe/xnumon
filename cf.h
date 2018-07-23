/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef CF_H
#define CF_H

#include "attrib.h"

#include <stdbool.h>
#include <stdint.h>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

bool cf_is_boolean(CFTypeRef) WUNRES NONNULL(1);
bool cf_is_string(CFTypeRef) WUNRES NONNULL(1);
bool cf_is_data(CFTypeRef) WUNRES NONNULL(1);
bool cf_is_array(CFTypeRef) WUNRES NONNULL(1);
bool cf_is_cert(CFTypeRef) WUNRES NONNULL(1);
char * cf_cstr(CFStringRef) MALLOC;
char ** cf_cstrv(CFArrayRef) MALLOC;
char ** cf_aev(CFArrayRef) MALLOC;
CFNumberRef cf_number(int64_t) MALLOC;
CFURLRef cf_url(const char *) MALLOC NONNULL(1);
CFDictionaryRef cf_dictionary1(CFTypeRef, CFTypeRef) MALLOC NONNULL(1,2);
CFPropertyListRef cf_plist_load(const char *) MALLOC;

#endif

