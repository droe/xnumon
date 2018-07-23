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
#include "debug.h"

#include <stdio.h>
#include <stdlib.h>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

config_t *config;

typedef struct {
	int origin;
	SecRequirementRef req;
} origin_req_tuple_t;

origin_req_tuple_t reqs[] = {
	{CODESIGN_ORIGIN_APPLE_SYSTEM, NULL},
	{CODESIGN_ORIGIN_MAC_APP_STORE, NULL},
	{CODESIGN_ORIGIN_DEVELOPER_ID, NULL},
	{CODESIGN_ORIGIN_APPLE_GENERIC, NULL},
	{CODESIGN_ORIGIN_TRUSTED_CA, NULL},
};

#define CREATE_REQ(REQ, REQSTR) \
{ \
	REQ = NULL; \
	if (SecRequirementCreateWithString(CFSTR(REQSTR), \
	                                   kSecCSDefaultFlags, \
	                                   &REQ) != errSecSuccess || !REQ) \
		return -1; \
}

int
codesign_init(config_t *cfg) {
	if (config)
		return -1;
	config = cfg;

	CREATE_REQ(reqs[0].req, "anchor apple");
	CREATE_REQ(reqs[1].req, "anchor apple generic and "
		"certificate leaf[field.1.2.840.113635.100.6.1.9] exists");
	CREATE_REQ(reqs[2].req, "anchor apple generic and "
		"certificate 1[field.1.2.840.113635.100.6.2.6] exists and "
		"certificate leaf[field.1.2.840.113635.100.6.1.13] exists");
	CREATE_REQ(reqs[3].req, "anchor apple generic");
	CREATE_REQ(reqs[4].req, "anchor trusted");
	return 0;
}

void
codesign_fini() {
	for (size_t i = 0; i < sizeof(reqs)/sizeof(origin_req_tuple_t); i++) {
		if (reqs[i].req) {
			CFRelease(reqs[i].req);
			reqs[i].req = NULL;
		}
	}
	config = NULL;
}

#undef CREATE_REQ

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
	cs->origin = other->origin;
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
		DEBUG(config->debug, "codesign_error",
		      "SecStaticCodeCreateWithPath(%s) => %i",
		      cpath, rv);
		cs->result = CODESIGN_RESULT_ERROR;
		return cs;
	}

	/* verify signature using embedded designated requirement */
	SecRequirementRef designated_req = NULL;
	rv = SecCodeCopyDesignatedRequirement(scode, kSecCSDefaultFlags,
	                                      &designated_req);
	switch (rv) {
	case errSecSuccess:
		break;
	case errSecCSUnsigned:
		cs->result = CODESIGN_RESULT_UNSIGNED;
		CFRelease(scode);
		return cs;
	default:
		DEBUG(config->debug, "codesign_error",
		      "SecCodeCopyDesignatedRequirement(%s) => %i",
		      cpath, rv);
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
	                                designated_req);
	CFRelease(designated_req);
	if (rv != errSecSuccess) {
		DEBUG(config->debug, "codesign_bad",
		      "SecStaticCodeCheckValidity(%s, full, designated_req)"
		      " => %i", cpath, rv);
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
		DEBUG(config->debug, "codesign_error",
		      "SecCodeCopySigningInformation(%s)"
		      " => %i", cpath, rv);
		cs->result = CODESIGN_RESULT_ERROR;
		return cs;
	}

	/* reduced set of flags, we are only checking requirements here */
	SecCSFlags csflags = kSecCSDefaultFlags|
	                     kSecCSCheckAllArchitectures|
	                     kSecCSStrictValidate;
	for (size_t i = 0; i < sizeof(reqs)/sizeof(origin_req_tuple_t); i++) {
		rv = SecStaticCodeCheckValidity(scode, csflags, reqs[i].req);
		if (rv == errSecSuccess) {
			cs->origin = reqs[i].origin;
			break;
		}
	}
	CFRelease(scode);
	if (rv != errSecSuccess) {
		/* signature is okay, but none of the requirements match;
		 * either the signature is from a self-signed certificate, a
		 * certificate issued by an untrusted CA, or it is an ad-hoc
		 * code signature.  Treat all of these as untrusted. */
		cs->result = CODESIGN_RESULT_UNTRUSTED;
	} else {
		cs->result = CODESIGN_RESULT_GOOD;
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

	/* extract identity-related info only for good signatures */
	if (cs->origin != CODESIGN_RESULT_GOOD)
		goto out;

	/* extract ident */
	CFStringRef ident = CFDictionaryGetValue(dict, kSecCodeInfoIdentifier);
	if (ident && cf_is_string(ident)) {
		cs->ident = cf_cstr(ident);
		if (!cs->ident) {
			CFRelease(dict);
			goto enomemout;
		}
	}

	/* extract Team ID, present on App Store and DevID signatures */
	CFStringRef teamid = CFDictionaryGetValue(dict,
	                                          kSecCodeInfoTeamIdentifier);
	if (teamid && cf_is_string(teamid)) {
		cs->teamid = cf_cstr(teamid);
		if (!cs->teamid) {
			CFRelease(dict);
			goto enomemout;
		}
	}

	/* skip certificate extraction unless origin is devid or trusted */
	if (cs->origin != CODESIGN_ORIGIN_DEVELOPER_ID &&
	    cs->origin != CODESIGN_ORIGIN_TRUSTED_CA)
		goto out;

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
	case CODESIGN_RESULT_UNTRUSTED:
		return "untrusted";
	case CODESIGN_RESULT_BAD:
		return "bad";
	case CODESIGN_RESULT_ERROR:
		return "error";
	default:
		/* this should never happen */
		return "undefined";
	}
}

const char *
codesign_origin_s(codesign_t *cs) {
	switch (cs->origin) {
	case CODESIGN_ORIGIN_APPLE_SYSTEM:
		return "system";
	case CODESIGN_ORIGIN_MAC_APP_STORE:
		return "appstore";
	case CODESIGN_ORIGIN_DEVELOPER_ID:
		return "devid";
	case CODESIGN_ORIGIN_APPLE_GENERIC:
		return "generic";
	case CODESIGN_ORIGIN_TRUSTED_CA:
		return "trusted";
	default:
		/* this should never happen if a signature is present */
		return "undefined";
	}
}

void
codesign_fprint(FILE *f, codesign_t *cs) {
	fprintf(f, "signature: %s\n", codesign_result_s(cs));
	if (cs->origin)
		fprintf(f, "origin: %s\n", codesign_origin_s(cs));
	if (cs->ident)
		fprintf(f, "ident: %s\n", cs->ident);
	if (cs->cdhash) {
		fprintf(f, "cdhash: ");
		for (size_t i = 0; i < cs->cdhashsz; i++) {
			fprintf(f, "%02x", cs->cdhash[i]);
		}
		fprintf(f, "\n");
	}
	if (cs->teamid)
		fprintf(f, "teamid: %s\n", cs->teamid);
	if (cs->devid)
		fprintf(f, "devid: %s\n", cs->devid);
}

