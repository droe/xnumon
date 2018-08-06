/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include "ipaddr.h"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>

char ipaddrtoa_buf[INET6_ADDRSTRLEN];

/*
 * If address family is empty/unset, returns nullstr (can be NULL).
 */
const char *
ipaddrtoa(ipaddr_t *addr, const char *nullstr) {
	if (ipaddr_is_empty(addr))
		return nullstr;
	if (!inet_ntop(addr->family, &addr->sin_addr,
	               ipaddrtoa_buf, sizeof(ipaddrtoa_buf)))
		return strerror(errno);
	return ipaddrtoa_buf;
}

/* ::1 - compare all 16 bytes */
static const unsigned char v6_localhost_bytes[] =
	{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
/* ::ffff:127.0.0.1 - compare size-3 bytes for 127.0.0.0/0 */
static const unsigned char v6_mapped_v4_localhost_bytes[] =
	{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x7f, 0, 0, 1 };

bool
ipaddr_is_localhost(ipaddr_t *addr) {
	switch (addr->family) {
	case AF_INET:
		return ((addr->sin_addr.s_addr & 0xff) == 0x7f);
	case AF_INET6:
		if (memcmp(addr->sin6_addr.s6_addr,
		           v6_localhost_bytes,
		           sizeof(v6_localhost_bytes)) == 0)
			return true;
		if (memcmp(addr->sin6_addr.s6_addr,
		           v6_mapped_v4_localhost_bytes,
		           sizeof(v6_mapped_v4_localhost_bytes) - 3) == 0)
			return true;
		return false;
	default:
		return false;
	}
}

const char *
protocoltoa(int protocol) {
	switch (protocol) {
	case IPPROTO_TCP:
		return "tcp";
	case IPPROTO_UDP:
		return "udp";
	case IPPROTO_SCTP:
		return "sctp";
	default:
		return "unknown";
	}
}

