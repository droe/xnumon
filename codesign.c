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
	if (cs->result)
		free(cs->result);
	if (cs->ident)
		free(cs->ident);
	for (int i = 0; i < cs->crtc; i++)
		if (cs->crtv[i])
			free(cs->crtv[i]);
	if (cs->crtv)
		free(cs->crtv);
	free(cs);
}

codesign_t *
codesign_dup(const codesign_t *other) {
	codesign_t *cs;

	cs = malloc(sizeof(codesign_t));
	if (!cs)
		return NULL;
	bzero(cs, sizeof(codesign_t));

	if (other->result) {
		cs->result = strdup(other->result);
		if (!cs->result)
			goto errout;
	}
	cs->error = other->error;
	if (other->ident) {
		cs->ident = strdup(other->ident);
		if (!cs->ident)
			goto errout;
	}
	if (other->crtv) {
		cs->crtc = other->crtc;
		cs->crtv = (char**)malloc(cs->crtc*sizeof(void*));
		if (!cs->crtv)
			goto errout;
		bzero(cs->crtv, cs->crtc);
		for (int i = 0; i < cs->crtc; i++) {
			cs->crtv[i] = strdup(other->crtv[i]);
			if (!cs->crtv[i])
				goto errout;
		}
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
		cs->result = strdup("error");
		if (!cs->result)
			goto enomemout;
		return cs;
	}

	SecRequirementRef req = NULL;
	rv = SecCodeCopyDesignatedRequirement(scode, kSecCSDefaultFlags, &req);
	switch (rv) {
	case noErr:
		break;
	case errSecCSUnsigned:
		cs->result = strdup("unsigned");
		CFRelease(scode);
		if (!cs->result)
			goto enomemout;
		return cs;
	default:
		cs->error = rv;
		cs->result = strdup("error");
		CFRelease(scode);
		if (!cs->result)
			goto enomemout;
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
		cs->result = strdup("bad");
		CFRelease(scode);
		if (!cs->result)
			goto enomemout;
		return cs;
	}

	/* retrieve information */
	CFDictionaryRef dict = NULL;
	rv = SecCodeCopySigningInformation(scode,
	                                   kSecCSSigningInformation,
	                                   &dict);
	CFRelease(scode);
	if (rv != noErr) {
		cs->error = rv;
		cs->result = strdup("error");
		if (!cs->result) {
			CFRelease(dict);
			goto enomemout;
		}
		return cs;
	}

	CFStringRef ident = CFDictionaryGetValue(dict, kSecCodeInfoIdentifier);
	cs->ident = cf_cstr(ident);
	if (!cs->ident) {
		CFRelease(dict);
		goto enomemout;
	}

	CFArrayRef chain = CFDictionaryGetValue(dict, kSecCodeInfoCertificates);
	CFIndex count = CFArrayGetCount(chain);
	cs->crtv = malloc(count*sizeof(void*));
	if (!cs->crtv) {
		CFRelease(dict);
		goto enomemout;
	}

	for (CFIndex i = 0; i < count; i++) {
		SecCertificateRef cert = (SecCertificateRef)
		                         CFArrayGetValueAtIndex(chain, i);
		if (!cert) {
			cs->crtv[i] = NULL;
		} else {
			CFStringRef ss = SecCertificateCopySubjectSummary(cert);
			if (!ss) {
				CFRelease(dict);
				goto enomemout;
			}
			cs->crtv[i] = cf_cstr(ss);
			CFRelease(ss);
			if (!cs->crtv[i]) {
				CFRelease(dict);
				goto enomemout;
			}
		}
		cs->crtc++;
	}
	CFRelease(dict);

	cs->result = strdup("good");
	if (!cs->result)
		goto enomemout;
	return cs;

enomemout:
	if (cs)
		codesign_free(cs);
	errno = ENOMEM;
	return NULL;
}

