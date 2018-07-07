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
	if (cs->cdhash)
		free(cs->cdhash);
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
	if (other->cdhash) {
		cs->cdhashsz = other->cdhashsz;
		cs->cdhash = malloc(cs->cdhashsz);
		if (!cs->cdhash)
			goto errout;
		memcpy(cs->cdhash, other->cdhash, cs->cdhashsz);
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
	if (rv != errSecSuccess) {
		cs->error = rv;
		cs->result = CODESIGN_RESULT_ERROR;
		return cs;
	}

	/* verify signature using embedded designated requirement */
	SecRequirementRef req = NULL;
	rv = SecCodeCopyDesignatedRequirement(scode, kSecCSDefaultFlags, &req);
	switch (rv) {
	case errSecSuccess:
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
	if (rv != errSecSuccess) {
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
	if (rv != errSecSuccess || !dict) {
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
		cs->result |= CODESIGN_RESULT_APPLE;
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
		cs->result = CODESIGN_RESULT_BAD; /* also clears _APPLE */
		return cs;
	}

	/* extract CDHash */
	CFDataRef cdhash = CFDictionaryGetValue(dict, kSecCodeInfoUnique);
	if (cdhash && cf_is_data(cdhash)) {
		cs->cdhashsz = CFDataGetLength(cdhash);
		cs->cdhash = malloc(cs->cdhashsz);
		if (!cs->cdhash) {
			CFRelease(dict);
			goto enomemout;
		}
		memcpy(cs->cdhash, CFDataGetBytePtr(cdhash), cs->cdhashsz);
	}

	/* Apple binaries have no Team ID or Developer ID */
	if (cs->result & CODESIGN_RESULT_APPLE)
		goto out;

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

	/* extract Developer ID from CN of first certificate in chain */
	CFArrayRef chain = CFDictionaryGetValue(dict,
	                                        kSecCodeInfoCertificates);
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

out:
	CFRelease(dict);
	/* avoid clearing CODESIGN_RESULT_APPLE */
	cs->result |= CODESIGN_RESULT_GOOD;
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

/*
 * Returns true iff the code signature is a genuine Apple binary, i.e. code
 * originating at Apple, not from developers part of the Developer ID program.
 * CODESIGN_RESULT_APPLE should only be set on good signatures, but for defense
 * in depth we are testing both flags anyway.
 */
bool
codesign_is_apple(codesign_t *cs) {
	return (cs->result & CODESIGN_RESULT_GOOD) &&
	       (cs->result & CODESIGN_RESULT_APPLE);
}

