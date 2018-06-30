/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include "codesign.h"

#include "cf.h"

#include <stdio.h>
#include <stdlib.h>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

void
codesign_free(codesign_t *cs) {
	if (cs->ident)
		free(cs->ident);
	if (cs->teamid)
		free(cs->teamid);
	if (cs->devid)
		free(cs->devid);
	free(cs);
}

codesign_t *
codesign_dup(const codesign_t *other) {
	codesign_t *cs;

	cs = malloc(sizeof(codesign_t));
	if (!cs)
		return NULL;
	bzero(cs, sizeof(codesign_t));

	cs->result = other->result;
	cs->error = other->error;
	if (other->ident) {
		cs->ident = strdup(other->ident);
		if (!cs->ident)
			goto errout;
	}
	if (other->teamid) {
		cs->teamid = strdup(other->teamid);
		if (!cs->teamid)
			goto errout;
	}
	if (other->devid) {
		cs->devid = strdup(other->devid);
		if (!cs->devid)
			goto errout;
	}
	return cs;
errout:
	codesign_free(cs);
	return NULL;
}

codesign_t *
codesign_new(const char *cpath) {
	codesign_t *cs;
	OSStatus rv;

	assert(cpath);

	cs = malloc(sizeof(codesign_t));
	if (!cs)
		goto enomemout;
	bzero(cs, sizeof(codesign_t));

	CFURLRef url = cf_url(cpath);
	if (!url)
		goto enomemout;

	SecStaticCodeRef scode = NULL;
	rv = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &scode);
	CFRelease(url);
	if (rv != noErr) {
		cs->error = rv;
		cs->result = CODESIGN_RESULT_ERROR;
		return cs;
	}

	/* verify signature using embedded designated requirement */
	SecRequirementRef req = NULL;
	rv = SecCodeCopyDesignatedRequirement(scode, kSecCSDefaultFlags, &req);
	switch (rv) {
	case noErr:
		break;
	case errSecCSUnsigned:
		cs->result = CODESIGN_RESULT_UNSIGNED;
		CFRelease(scode);
		return cs;
	default:
		cs->error = rv;
		cs->result = CODESIGN_RESULT_ERROR;
		CFRelease(scode);
		return cs;
	}
	rv = SecStaticCodeCheckValidity(scode,
	                                kSecCSDefaultFlags|
	                                kSecCSCheckAllArchitectures|
	                                kSecCSStrictValidate|
	                                kSecCSCheckNestedCode|
	                                kSecCSEnforceRevocationChecks|
	                                kSecCSConsiderExpiration,
	                                req);
	CFRelease(req);
	if (rv != noErr) {
		cs->result = CODESIGN_RESULT_BAD;
		CFRelease(scode);
		return cs;
	}

	/* retrieve information from signature */
	CFDictionaryRef dict = NULL;
	rv = SecCodeCopySigningInformation(scode,
	                                   kSecCSSigningInformation|
	                                   kSecCSInternalInformation|
	                                   kSecCSRequirementInformation,
	                                   &dict);
	if (rv != noErr || !dict) {
		CFRelease(scode);
		cs->error = rv;
		cs->result = CODESIGN_RESULT_ERROR;
		return cs;
	}

	/* copy ident string; signed implies ident string is present */
	CFStringRef ident = CFDictionaryGetValue(dict, kSecCodeInfoIdentifier);
	if (ident && cf_is_string(ident)) {
		cs->ident = cf_cstr(ident);
		if (!cs->ident) {
			CFRelease(scode);
			CFRelease(dict);
			goto enomemout;
		}
	} else {
		CFRelease(scode);
		CFRelease(dict);
		cs->result = CODESIGN_RESULT_BAD;
		return cs;
	}
	assert(ident && cs->ident);

	/* verify signing certificate was issued by appropriate Apple CA; this
	 * ensures that a non-Apple binary cannot carry an com.apple ident */
	CFStringRef anchor;
	if (CFStringHasPrefix(ident, CFSTR("com.apple."))) {
		anchor = CFSTR("anchor apple");
	} else {
		anchor = CFSTR("anchor apple generic");
	}
	req = NULL;
	rv = SecRequirementCreateWithString(anchor, kSecCSDefaultFlags, &req);
	if (rv != errSecSuccess || !req) {
		CFRelease(scode);
		CFRelease(dict);
		goto enomemout;
	}
	/* reduced set of flags, we are only checking the anchor here */
	rv = SecStaticCodeCheckValidity(scode,
	                                kSecCSDefaultFlags|
	                                kSecCSCheckAllArchitectures|
	                                kSecCSStrictValidate,
	                                req);
	CFRelease(scode);
	CFRelease(req);
	if (rv != errSecSuccess) {
		CFRelease(dict);
		free(cs->ident);
		cs->ident = NULL;
		cs->result = CODESIGN_RESULT_BAD;
		return cs;
	}

	/* extract Team ID associated with the signing Developer ID */
	CFStringRef teamid = CFDictionaryGetValue(dict,
	                                          kSecCodeInfoTeamIdentifier);
	if (teamid && cf_is_string(teamid)) {
		cs->teamid = cf_cstr(teamid);
		if (!cs->teamid) {
			CFRelease(dict);
			goto enomemout;
		}
	}

	/* extract first certificate in chain */
	CFArrayRef chain = CFDictionaryGetValue(dict, kSecCodeInfoCertificates);
	if (chain && cf_is_array(chain) && CFArrayGetCount(chain) >= 1) {
		SecCertificateRef crt =
		        (SecCertificateRef)CFArrayGetValueAtIndex(chain, 0);
		if (crt && cf_is_cert(crt)) {
			CFStringRef s = SecCertificateCopySubjectSummary(crt);
			if (!s) {
				CFRelease(dict);
				goto enomemout;
			}
			cs->devid = cf_cstr(s);
			CFRelease(s);
			if (!cs->devid) {
				CFRelease(dict);
				goto enomemout;
			}
		}
	}

	CFRelease(dict);
	cs->result = CODESIGN_RESULT_GOOD;
	return cs;

enomemout:
	if (cs)
		codesign_free(cs);
	errno = ENOMEM;
	return NULL;
}

const char *
codesign_result_s(codesign_t *cs) {
	switch (cs->result) {
	case CODESIGN_RESULT_UNSIGNED:
		return "unsigned";
	case CODESIGN_RESULT_GOOD:
		return "good";
	case CODESIGN_RESULT_BAD:
		return "bad";
	case CODESIGN_RESULT_ERROR:
		return "error";
	default:
		/* this should never happen */
		return "undefined";
	}
}

