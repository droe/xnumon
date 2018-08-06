/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef IPADDR_H
#define IPADDR_H

#include "attrib.h"

#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif

typedef struct ipaddr {
	sa_family_t family;
	union {
		/* AF_INET */
		uint32_t ev_addr;
		struct in_addr sin_addr;
		/* AF_INET6 */
		uint32_t ev6_addr[4];
		struct in6_addr sin6_addr;
	};
} ipaddr_t;

const char * ipaddrtoa(ipaddr_t *, const char *) NONNULL(1) WUNRES;
bool ipaddr_is_localhost(ipaddr_t *) NONNULL(1) WUNRES;
#define ipaddr_is_empty(PIPADDR) ((PIPADDR)->family == 0)

const char * protocoltoa(int) WUNRES;

#endif

