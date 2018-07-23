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

