/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef HASHES_H
#define HASHES_H

#include "attrib.h"

#include <sys/types.h>

#define MD5SZ    16
#define SHA1SZ   20
#define SHA256SZ 32

typedef struct __attribute__((packed)) {
	unsigned char md5[MD5SZ];
	unsigned char sha1[SHA1SZ];
	unsigned char sha256[SHA256SZ];
} hashes_t;

int hashes_fd(off_t *, hashes_t *, int, int) NONNULL(1,2);
int hashes_path(off_t *, hashes_t *, int, const char *) NONNULL(1,2,4);
int hashes_parse(const char *) NONNULL(1);
const char * hashes_flags_s(int);

#define HASH_MD5                1
#define HASH_SHA1               2
#define HASH_SHA256             4
#define HASH_MD5_SHA1           (HASH_MD5|HASH_SHA1)
#define HASH_MD5_SHA256         (HASH_MD5|HASH_SHA256)
#define HASH_SHA1_SHA256        (HASH_SHA1|HASH_SHA256)
#define HASH_MD5_SHA1_SHA256    (HASH_MD5|HASH_SHA1|HASH_SHA256)
#define HASH_ALL                HASH_MD5_SHA1_SHA256

#endif

