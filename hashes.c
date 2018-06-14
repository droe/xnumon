/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include "hashes.h"
#include "map.h"

#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <string.h>

#ifdef USE_OPENSSL
#include <openssl/md5.h>
#include <openssl/sha.h>
#define md5_ctx_t       MD5_CTX
#define md5_init        MD5_Init
#define md5_update      MD5_Update
#define md5_final       MD5_Final
#define sha1_ctx_t      SHA_CTX
#define sha1_init       SHA1_Init
#define sha1_update     SHA1_Update
#define sha1_final      SHA1_Final
#define sha256_ctx_t    SHA256_CTX
#define sha256_init     SHA256_Init
#define sha256_update   SHA256_Update
#define sha256_final    SHA256_Final
#else /* !USE_OPENSSL */
#include <CommonCrypto/CommonDigest.h>
#define md5_ctx_t       CC_MD5_CTX
#define md5_init        CC_MD5_Init
#define md5_update      CC_MD5_Update
#define md5_final       CC_MD5_Final
#define sha1_ctx_t      CC_SHA1_CTX
#define sha1_init       CC_SHA1_Init
#define sha1_update     CC_SHA1_Update
#define sha1_final      CC_SHA1_Final
#define sha256_ctx_t    CC_SHA256_CTX
#define sha256_init     CC_SHA256_Init
#define sha256_update   CC_SHA256_Update
#define sha256_final    CC_SHA256_Final
#endif /* !USE_OPENSSL */

#define RDBUFSZ 1024*32

#define CTX(H)          H##_ctx_t H##ctx;
#define INIT(H)         H##_init(&H##ctx);
#define UPDATE(H)       H##_update(&H##ctx, buf, n);
#define FINAL(H)        H##_final(hashes->H, &H##ctx);

#define HASHES_FD(N,...)                                        \
static int                                                      \
hashes_fd_##N(off_t *sz, hashes_t *hashes, int fd) {            \
	unsigned char buf[RDBUFSZ];                             \
	ssize_t n;                                              \
	off_t count;                                            \
	MAP(CTX, __VA_ARGS__)                                   \
	count = 0;                                              \
	MAP(INIT, __VA_ARGS__)                                  \
	for (;;) {                                              \
		n = read(fd, buf, sizeof(buf));                 \
		if (n == 0)                                     \
			break;                                  \
		else if (n == -1) {                             \
			bzero(hashes, sizeof(hashes_t));        \
			return -1;                              \
		}                                               \
		count += n;                                     \
		MAP(UPDATE, __VA_ARGS__)                        \
	}                                                       \
	*sz = count;                                            \
	MAP(FINAL, __VA_ARGS__)                                 \
	return 0;                                               \
}

HASHES_FD(md5, md5)
HASHES_FD(sha1, sha1)
HASHES_FD(sha256, sha256)
HASHES_FD(md5_sha1, md5, sha1)
HASHES_FD(sha1_sha256, sha1, sha256)
HASHES_FD(md5_sha256, md5, sha256)
HASHES_FD(md5_sha1_sha256, md5, sha1, sha256)

int
hashes_fd(off_t *sz, hashes_t *hashes, int flags, int fd) {
	switch (flags) {
	case HASH_MD5:
		return hashes_fd_md5(sz, hashes, fd);
	case HASH_SHA1:
		return hashes_fd_sha1(sz, hashes, fd);
	case HASH_SHA256:
		return hashes_fd_sha256(sz, hashes, fd);
	case HASH_MD5_SHA1:
		return hashes_fd_md5_sha1(sz, hashes, fd);
	case HASH_SHA1_SHA256:
		return hashes_fd_sha1_sha256(sz, hashes, fd);
	case HASH_MD5_SHA256:
		return hashes_fd_md5_sha256(sz, hashes, fd);
	case HASH_MD5_SHA1_SHA256:
		return hashes_fd_md5_sha1_sha256(sz, hashes, fd);
	}
	return -1;
}

int
hashes_path(off_t *sz, hashes_t *hashes, int flags, const char *path) {
	int fd, rv;

	assert(!!strncmp(path, "/dev/", 5));
	assert(flags & HASH_ALL);

	if ((fd = open(path, O_RDONLY)) == -1)
		return -1;

	rv = hashes_fd(sz, hashes, flags, fd);
	close(fd);
	return rv;
}

int
hashes_parse(const char *hashspec) {
	const char *p;
	size_t sz;
	int flags;

	flags = 0;
	p = hashspec;
	for (;;) {
		sz = 0;
		while ((p[sz] != '\0') && (p[sz] != ',') && (p[sz] != ' '))
			sz++;
		if (sz == 3 && !memcmp(p, "md5", sz))
			flags |= HASH_MD5;
		if (sz == 4 && !memcmp(p, "sha1", sz))
			flags |= HASH_SHA1;
		if (sz == 6 && !memcmp(p, "sha256", sz))
			flags |= HASH_SHA256;
		if (!p[sz])
			break;
		p += sz + 1;
		while ((p[sz] != '\0') && (p[sz] == ' '))
			sz++;
	}
	if (flags == 0)
		return -1;
	return flags;
}

static const char *hflags[] = {
	"none",
	"md5",
	"sha1",
	"md5,sha1",
	"sha256",
	"md5,sha256",
	"sha1,sha256",
	"md5,sha1,sha256"
};

const char *
hashes_flags_s(int flags) {
	return hflags[flags];
}

