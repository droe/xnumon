/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2019, Daniel Roethlisberger <daniel@roe.ch>.
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

/* CarbonCore MacErrors.h */
#ifndef kPOSIXErrorESRCH
#define kPOSIXErrorESRCH 100003
#endif

static config_t *config;

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

	/*
	 * Order needs to match the order of the origin values in reqs above;
	 * should be most specific first.  Will be tested from top to bottom
	 * until the first fulfilled requirement.  Current list obtained from
	 * 10.11.6 El Capitan using `spctl --list --type execute`.
	 */
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
	if (cs->cdhash)
		free(cs->cdhash);
	if (cs->ident)
		free(cs->ident);
	if (cs->teamid)
		free(cs->teamid);
	if (cs->certcn)
		free(cs->certcn);
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
	if (other->certcn) {
		cs->certcn = strdup(other->certcn);
		if (!cs->certcn)
			goto errout;
	}
	return cs;
errout:
	codesign_free(cs);
	return NULL;
}

/*
 * Extract code signature meta-data from either an on-disk executable or a pid.
 * Either cpath must be NULL or pid must be -1.
 *
 * We cannot safely acquire code signature information by pid in xnumon.
 * Nevertheless, the chkcs utility can acquire code signature information from
 * running processes for experimentation and comparison against codesign(1).
 *
 * Returns NULL and errno = ENOENT if the path could not be found.
 * Returns NULL and errno = ESRCH if the pid could not be found.
 * Returns NULL and errno = ENOMEM if out of memory.
 * All other, unexpected errors return a newly allocated codesign_t with result
 * CODESIGN_RESULT_ERROR.
 */
codesign_t *
codesign_new(const char *cpath, pid_t pid) {
	codesign_t *cs;
	OSStatus rv;

	assert((cpath && pid == (pid_t)-1) || (!cpath && pid != (pid_t)-1));

	cs = malloc(sizeof(codesign_t));
	if (!cs)
		goto enomemout;
	bzero(cs, sizeof(codesign_t));

	SecStaticCodeRef scode = NULL;
	if (cpath) {
		CFURLRef url = cf_url(cpath);
		if (!url)
			goto enomemout;
		rv = SecStaticCodeCreateWithPath(url,
		                                 kSecCSDefaultFlags,
		                                 &scode);
		CFRelease(url);
		switch (rv) {
		case errSecSuccess:
			break;
		case errSecCSStaticCodeNotFound:
			errno = ENOENT;
			goto errout;
		default:
			DEBUG(config->debug,
			      "codesign_error",
			      "SecStaticCodeCreateWithPath(%s) => %i",
			      cpath, rv);
			cs->result = CODESIGN_RESULT_ERROR;
			return cs;
		}
	} else {
		CFNumberRef cfnpid = cf_number(pid);
		if (!cfnpid)
			goto enomemout;
		CFDictionaryRef cfdpid = cf_dictionary1(kSecGuestAttributePid,
		                                        cfnpid);
		if (!cfdpid) {
			CFRelease(cfnpid);
			goto enomemout;
		}
		rv = SecCodeCopyGuestWithAttributes(NULL,
		                                    cfdpid,
		                                    kSecCSDefaultFlags,
		                                    (SecCodeRef*)&scode);
		CFRelease(cfdpid);
		CFRelease(cfnpid);
		switch (rv) {
		case errSecSuccess:
			break;
		case kPOSIXErrorESRCH: /* 100003 */
			errno = ESRCH;
			goto errout;
		default:
			DEBUG(config->debug,
			      "codesign_error",
			      "SecCodeCopyGuestWithAttributes(%i) => %i",
			      pid, rv);
			cs->result = CODESIGN_RESULT_ERROR;
			return cs;
		}
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
		/* fallthrough */
	case errSecCSBadObjectFormat:
		cs->result = CODESIGN_RESULT_ERROR;
		CFRelease(scode);
		return cs;
	}
	SecCSFlags csflags = kSecCSDefaultFlags|
		             kSecCSStrictValidate|
		             kSecCSEnforceRevocationChecks|
		             kSecCSConsiderExpiration;
	if (cpath) {
		csflags |= kSecCSCheckAllArchitectures|
		           kSecCSCheckNestedCode|
		           kSecCSDoNotValidateResources;
		rv = SecStaticCodeCheckValidity(scode,
		                                csflags,
		                                designated_req);
	} else {
		rv = SecCodeCheckValidity((SecCodeRef)scode,
		                          csflags,
		                          designated_req);
	}
	const char *badreason;
	if (config->debug) {
		switch (rv) {
		case errSecSuccess:
			badreason = "success";
			break;
		case CSSMERR_TP_CERT_REVOKED:
			/* includes revocation of certs seen on malware */
			badreason = "revoked";
			break;
		default:
			badreason = "other";
			break;
		}
	}
	if (cpath) {
		DEBUG(config->debug && rv != errSecSuccess,
		      "codesign_bad",
		      "SecStaticCodeCheckValidity(%s, full, designated_req)"
		      " => %i (%s)", cpath, rv, badreason);
	} else {
		DEBUG(config->debug && rv != errSecSuccess,
		      "codesign_bad",
		      "SecCodeCheckValidity(%i, full, designated_req)"
		      " => %i (%s)", pid, rv, badreason);
	}
	CFRelease(designated_req);
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
		DEBUG(config->debug, "codesign_error",
		      "SecCodeCopySigningInformation(%s)"
		      " => %i", cpath, rv);
		cs->result = CODESIGN_RESULT_ERROR;
		return cs;
	}

	/* reduced set of flags, we are only checking requirements here */
	csflags = kSecCSDefaultFlags|
	          kSecCSStrictValidate;
	if (cpath)
		csflags |= kSecCSCheckAllArchitectures|
		           kSecCSDoNotValidateResources;
	for (size_t i = 0; i < sizeof(reqs)/sizeof(origin_req_tuple_t); i++) {
		if (cpath)
			rv = SecStaticCodeCheckValidity(scode,
			                                csflags,
			                                reqs[i].req);
		else
			rv = SecCodeCheckValidity((SecCodeRef)scode,
			                          csflags,
			                          reqs[i].req);
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
	if (cs->result != CODESIGN_RESULT_GOOD)
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

	/* extract Team ID */
	CFStringRef teamid = CFDictionaryGetValue(dict,
	                                          kSecCodeInfoTeamIdentifier);
	if (teamid && cf_is_string(teamid)) {
		cs->teamid = cf_cstr(teamid);
		if (!cs->teamid) {
			CFRelease(dict);
			goto enomemout;
		}
	}

	/* skip certificate CN extraction where it holds no interesting data */
	if (cs->origin == CODESIGN_ORIGIN_APPLE_SYSTEM ||
	    cs->origin == CODESIGN_ORIGIN_MAC_APP_STORE)
		goto out;

	/* extract CN of first certificate in chain */
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
			cs->certcn = cf_cstr(s);
			CFRelease(s);
			if (!cs->certcn) {
				CFRelease(dict);
				goto enomemout;
			}
		}
	}

out:
	CFRelease(dict);
	return cs;

enomemout:
	errno = ENOMEM;
errout:
	if (cs)
		codesign_free(cs);
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
	if (cs->cdhash) {
		fprintf(f, "cdhash: ");
		for (size_t i = 0; i < cs->cdhashsz; i++) {
			fprintf(f, "%02x", cs->cdhash[i]);
		}
		fprintf(f, "\n");
	}
	if (cs->ident)
		fprintf(f, "ident: %s\n", cs->ident);
	if (cs->teamid)
		fprintf(f, "teamid: %s\n", cs->teamid);
	if (cs->certcn)
		fprintf(f, "certcn: %s\n", cs->certcn);
}

