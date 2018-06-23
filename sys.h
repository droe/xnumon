/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#ifndef SYS_H
#define SYS_H

#include "attrib.h"

#include <sys/types.h>
#include <stdint.h>
#include <time.h>

typedef struct {
	mode_t mode;
	uid_t uid;
	gid_t gid;
	dev_t dev;
	ino_t ino;
	/*dev_t rdev;*/
	off_t size;
	struct timespec mtime;
	struct timespec ctime;
	struct timespec btime;
} stat_attr_t;

char * sys_pidpath(pid_t) MALLOC;
char * sys_pidcwd(pid_t) MALLOC;
int sys_pidbsdinfo(struct timespec *, pid_t *,
                   uid_t *, uint32_t *, uid_t *, gid_t *, uid_t *, gid_t *,
                   dev_t *dev, /* missing addr */
                   pid_t) WUNRES;
pid_t * sys_pidlist(int *) MALLOC NONNULL(1);

gid_t sys_gidbyname(const char *) NONNULL(1);

const char * sys_ttydevname(dev_t) WUNRES;

int sys_pathattr(stat_attr_t *, const char *) NONNULL(1,2);
int sys_fdattr(stat_attr_t *, int) NONNULL(1);

int sys_basenamecmp(const char *restrict, const char *restrict) WUNRES;
char * sys_realpath(const char *restrict, const char *restrict) MALLOC;

int sys_limit_nofile(size_t);

int sys_pidf_open(const char *) NONNULL(1) WUNRES;
int sys_pidf_write(int) WUNRES;
void sys_pidf_close(int, const char *) NONNULL(2);

typedef int (*sys_dir_eachfile_cb_t)(const char *, void *) NONNULL(1) WUNRES;
int sys_dir_eachfile(const char *, sys_dir_eachfile_cb_t, void *) NONNULL(1,2) WUNRES;

char * sys_which(const char *, const char *) MALLOC NONNULL(1,2);

#endif

