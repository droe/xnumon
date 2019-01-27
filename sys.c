/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2019, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

#include "sys.h"

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <libproc.h>
#include <grp.h>
#include <fts.h>
#include <assert.h>

char *
sys_pidpath(pid_t pid) {
	char buf[PROC_PIDPATHINFO_MAXSIZE];

	errno = 0;
	if (pid == 0)
		return strdup("/System/Library/Kernels/kernel");
	if (proc_pidpath(pid, buf, sizeof(buf)) <= 0)
		return NULL;
	return strdup(buf);
}

char *
sys_pidcwd(pid_t pid) {
	struct proc_vnodepathinfo vpi;
	int rv;

	if (pid == 0)
		return strdup("/");
	rv = proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &vpi, sizeof(vpi));
	if (rv <= 0)
		return NULL;
	return strdup(vpi.pvi_cdir.vip_path);
}

int
sys_pidbsdinfo(struct timespec *tv, pid_t *ppid, pid_t pid) {
	struct proc_bsdinfo pbi;
	int rv;

	rv = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &pbi,
	                  sizeof(struct proc_bsdinfo));
	if (rv <= 0)
		return -1;

	if (tv) {
		tv->tv_sec = pbi.pbi_start_tvsec;
		tv->tv_nsec = pbi.pbi_start_tvusec*1000;
	}
	if (ppid)
		*ppid = pbi.pbi_ppid;
	return 0;
}

pid_t *
sys_pidlist(int *pidc) {
	pid_t *pidv;
	int sz;
	int n;

	for (;;) {
		n = proc_listallpids(NULL, 0);
		if (n <= 0)
			return NULL;
		sz = (n + 8) * sizeof(pid_t);
		pidv = malloc(sz);
		if (!pidv)
			return NULL;
		n = proc_listallpids(pidv, sz);
		if (n <= 0) {
			free(pidv);
			return NULL;
		}
		if (n*2 >= sz) {
			free(pidv);
			continue;
		}
		*pidc = n;
		return pidv;
	}
}

/*
 * Returns group number of group with name *name*, or 0 if group not found.
 */
gid_t
sys_gidbyname(const char *name) {
	struct group *gr;

	gr = getgrnam(name);
	if (!gr)
		return 0;
	return gr->gr_gid;
}

dev_t
sys_devbypath(const char *path) {
	struct stat ss;

	if (stat(path, &ss) == -1)
		return -1;

	return ss.st_rdev;
}

const char *
sys_ttydevname(dev_t dev) {
	return devname(dev, S_IFCHR);
}

int
sys_fdattr(stat_attr_t *sa, int fd) {
	struct stat ss;

	if (fstat(fd, &ss) == -1)
		return -1;

	sa->mode = ss.st_mode;
	sa->uid = ss.st_uid;
	sa->gid = ss.st_gid;
	sa->size = ss.st_size;
	sa->mtime = ss.st_mtimespec;
	sa->ctime = ss.st_ctimespec;
	sa->btime = ss.st_birthtimespec;
	sa->dev = ss.st_dev;
	sa->ino = ss.st_ino;
	return 0;
}

int
sys_pathattr(stat_attr_t *sa, const char *path) {
	struct stat ss;

	if (stat(path, &ss) == -1)
		return -1;

	sa->mode = ss.st_mode;
	sa->uid = ss.st_uid;
	sa->gid = ss.st_gid;
	sa->size = ss.st_size;
	sa->mtime = ss.st_mtimespec;
	sa->ctime = ss.st_ctimespec;
	sa->btime = ss.st_birthtimespec;
	sa->dev = ss.st_dev;
	sa->ino = ss.st_ino;
	return 0;
}

int
sys_fd_setblocking(int fd) {
	int opts;

	opts = fcntl(fd, F_GETFL);
	if (opts == -1)
		return -1;
	opts &= ~O_NONBLOCK;
	if (fcntl(fd, F_SETFL, opts) == -1)
		return -1;
	return 0;
}

int
sys_basenamecmp(const char *restrict s1, const char *restrict s2) {
	const char *p1, *p2;

	if (!s1 && !s2)
		return 0;
	if (s1 && !s2)
		return 1;
	if (!s1 && s2)
		return -1;

	for (p1 = s1 + strlen(s1); p1 >= s1 && *p1 != '/'; p1--);
	for (p2 = s2 + strlen(s2); p2 >= s2 && *p2 != '/'; p2--);
	return strcmp(++p1, ++p2);
}

/*
 * Returns a newly allocated absolute path constructed from path and cwd that
 * must be freed by the caller.
 */
char *
sys_realpath(const char *restrict path, const char *restrict cwd) {
	char *rp, *res;
	int rv;

	errno = 0;
	if (!path)
		return NULL;
	if (path[0] == '/')
		return realpath(path, NULL);
	if (!cwd)
		return NULL;
	rv = asprintf(&rp, "%s/%s", cwd, path);
	if (rv == -1)
		return NULL;
	res = realpath(rp, NULL);
	free(rp);
	return res;
}

/*
 * Variant of sys_realpath that only resolves that directory portion, not the
 * file portion.
 *
 * This implementation is more wasteful than would be possible in that it does
 * too many allocations.
 */
char *
sys_realdir(const char *restrict path, const char *restrict cwd) {
	char *sep, *udir, *rdir, *p;
	int rerrno;

	if (path[0] == '/') {
		udir = strdup(path);
	} else {
		if (!cwd)
			return NULL;
		(void)asprintf(&udir, "%s/%s", cwd, path);
	}
	if (!udir)
		return NULL;

	sep = strrchr(udir, '/');
	assert(sep);
	*sep = '\0';
	rdir = sys_realpath(udir, NULL);
	if (!rdir) {
		rerrno = errno;
		free(udir);
		errno = rerrno;
		return NULL;
	}
	(void)asprintf(&p, "%s/%s", rdir, sep+1);
	rerrno = errno;
	free(rdir);
	free(udir);
	errno = rerrno;
	return p;
}

/*
 * Returns a newly allocated absolute path constructed from the content of
 * symlink path and it's dirname.  Path must not end in '/'.
 * Path may be temporarily modified but will be restored before returning.
 *
 * To resolve the symlink, the result should be passed to sys_realpath.
 */
char *
sys_readlink(const char *path) {
	char buf[PATH_MAX];
	char *target, *p;
	ssize_t n;

	if (!path || path[0] != '/')
		return NULL;

	/* readlink does not append a NUL character, PATH_MAX includes NUL */
	n = readlink(path, buf, sizeof(buf) - 1);
	if (n == -1)
		return NULL;
	buf[n] = '\0';
	sys_strip_path_noop(buf);

	if (buf[0] == '/')
		return strdup(buf);

	/* temporarily modify path in order to avoid allocation and copy */
	p = strrchr(path, '/');
	assert(p);
	*p = '\0';
	asprintf(&target, "%s/%s", path, buf);
	*p = '/';
	return target;
}

/*
 * Strip noop sequences from path, transforms /./ => / and // => / and
 * removes trailing slashes.
 * Purely a string operation, does not perform any file system access.
 * Does not follow any symlinks.  Does not resolve .. to parent directories.
 *
 * Modifies path directly and always succeeds.
 */
void
sys_strip_path_noop(char *path) {
	char *src, *dst;

	for (src = dst = path; *src; src++, dst++) {
		if (*src == '/') {
			for (;;) {
				if (*(src + 1) == '/')
					src++;
				else if (*(src + 1) == '.' && *(src + 2) == '/')
					src += 2;
				else
					break;
			}
		} else {
			*dst = *src;
		}
	}
	*(dst--) = '\0';
	while (dst >= path && *dst == '/')
		*(dst--) = '\0';
}

/*
 * Returns 1 if path exists and is a symbolic link.
 * Returns 0 if path exists and is not a symbolic link.
 * Returns -1 on errors, including if path does not exist.
 */
int
sys_islnk(const char *path) {
	struct stat ss;

	if (lstat(path, &ss) == -1)
		return -1;

	return S_ISLNK(ss.st_mode) ? 1 : 0;
}

/*
 * Set the limit on the number of open file descriptors to `no`.
 * The default on macOS on the shell is a measly 256.
 */
int
sys_limit_nofile(size_t no) {
	struct rlimit rl;

	rl.rlim_cur = no;
	rl.rlim_max = no;
	if (setrlimit(RLIMIT_NOFILE, &rl) == -1)
		return -1;
	return 0;
}

/*
 * Open and lock process ID file fn.
 * Returns open file descriptor on success or -1 on errors.
 */
int
sys_pidf_open(const char *fn)
{
	int fd;

	if ((fd = open(fn, O_RDWR|O_CREAT, 0660)) == -1) {
		fprintf(stderr, "Failed to open '%s': %s (%i)\n",
		                fn, strerror(errno), errno);
		return -1;
	}
	if (flock(fd, LOCK_EX|LOCK_NB) == -1) {
		fprintf(stderr, "Failed to lock '%s': %s (%i)\n",
		                fn, strerror(errno), errno);
		close(fd);
		return -1;
	}
	return fd;
}

/*
 * Write process ID to open process ID file descriptor fd.
 * Returns 0 on success, -1 on errors.
 */
int
sys_pidf_write(int fd)
{
	char pidbuf[4*sizeof(pid_t)];
	int rv;
	ssize_t n;

	rv = snprintf(pidbuf, sizeof(pidbuf), "%d\n", getpid());
	if (rv == -1 || rv >= (int)sizeof(pidbuf))
		return -1;

	n = write(fd, pidbuf, strlen(pidbuf));
	if (n < (ssize_t)strlen(pidbuf))
		return -1;

	rv = fsync(fd);
	if (rv == -1)
		return -1;

	rv = fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
	if (rv == -1)
		return -1;

	return 0;
}

/*
 * Close and remove open process ID file before quitting.
 */
void
sys_pidf_close(int fd, const char *fn)
{
	unlink(fn);
	close(fd);
}

/*
 * Iterate over all files in a directory hierarchy, calling the callback
 * cb for each file, passing the filename and arg as arguments.  Files and
 * directories beginning with a dot are skipped.  Symlinks pointing to
 * directories are followed, all other symlinks are returned.
 */
int
sys_dir_eachfile_l(const char *dirname, sys_dir_eachfile_cb_t cb, void *arg)
{
	FTS *tree;
	FTSENT *node;
	char *paths[2];
	int rv = 0;

	paths[1] = NULL;
	paths[0] = strdup(dirname);
	if (!paths[0])
		return -1;

	tree = fts_open(paths, FTS_NOCHDIR|FTS_COMFOLLOW|FTS_PHYSICAL, NULL);
	if (!tree) {
		fprintf(stderr, "Cannot open directory '%s': %s\n",
		                dirname, strerror(errno));
		rv = -1;
		goto out1;
	}

	while ((node = fts_read(tree))) {
		if (node->fts_level > 0 && node->fts_name[0] == '.')
			fts_set(tree, node, FTS_SKIP);
		else if (node->fts_info & (FTS_F | FTS_SLNONE)) {
			rv = cb(node->fts_path, arg);
			if (rv == -1)
				goto out2;
		} else if (node->fts_info & FTS_SL) {
			rv = sys_dir_eachfile_l(node->fts_path, cb, arg);
			if (rv == -1)
				goto out2;
		}
	}
	if (errno) {
		fprintf(stderr, "Error reading directory entry: %s\n",
		                strerror(errno));
		rv = -1;
		goto out2;
	}

out2:
	fts_close(tree);

out1:
	free(paths[0]);
	return rv;
}

char *
sys_which(const char *command, const char *path) {
	char *p;
	char *tok;
	char *cand;

	p = strdup(path);
	if (!p)
		return NULL;
	tok = strtok(p, ":");
	while (tok) {
		asprintf(&cand, "%s/%s", tok, command);
		if (!cand) {
			free(p);
			return NULL;
		}
		if (access(cand, X_OK) == 0) {
			free(p);
			return cand;
		}
		free(cand);
		tok = strtok(NULL, ":");
	}
	free(p);
	return NULL;
}


