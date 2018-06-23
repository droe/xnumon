/*-
 * xnumon - monitor macOS for malicious activity
 * https://www.roe.ch/xnumon
 *
 * Copyright (c) 2017-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * All rights reserved.
 *
 * Licensed under the Open Software License version 3.0.
 */

/*
 * Process monitoring core.
 *
 * Plenty of refactoring opportunities here.
 */

#include "procmon.h"

#include "proc.h"
#include "hashes.h"
#include "cachehash.h"
#include "cachecsig.h"
#include "time.h"
#include "work.h"
#include "atomic.h"
#include "strset.h"

#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>

static config_t *config;

static tommy_list kqlist;
static uint64_t kqsize;         /* current number of elements in kqlist */
static uint64_t kqlookups;      /* counts total number of lookups in kq */
static uint64_t kqnotfounds;    /* counts no preloaded image found in kq */
static uint64_t kqtimeouts;     /* counts preloaded imgs removed due max TTL */
static uint64_t kqskips;        /* counts non-matching entries skipped in kq */

static atomic32_t images;
static uint64_t eimiss_bypid;   /* counts various missed image conditions */
static uint64_t eimiss_forksubj;
static uint64_t eimiss_execsubj;
static uint64_t eimiss_execinterp;
static uint64_t eimiss_chdirsubj;
static uint64_t eimiss_getcwd;
static atomic64_t ooms;         /* counts events impaired due to OOM */

strset_t *suppress_image_exec_by_ident;
strset_t *suppress_image_exec_by_path;

static int image_exec_work(image_exec_t *);

/*
 * Ownership of path will be transfered to image_exec; caller must not assume
 * that path still exists after calling this function.  Path is also freed when
 * this function fails and returns NULL.
 */
static image_exec_t *
image_exec_new(char *path) {
	image_exec_t *image;

	assert(path);

	image = malloc(sizeof(image_exec_t));
	if (!image) {
		free(path);
		atomic64_inc(&ooms);
		return NULL;
	}
	bzero(image, sizeof(image_exec_t));
	pthread_mutex_init(&image->refsmutex, NULL);
	image->refs = 1;
#ifdef DEBUG_REFS
	fprintf(stderr, "DEBUG_REFS: image_exec_new(%p) refs=%zu\n",
	                image, image->refs);
#endif
	image->path = path;
	image->fd = -1;
	image->hdr.type = LOGEVT_IMAGE_EXEC;
	image->hdr.le_work = (__typeof__(image->hdr.le_work))image_exec_work;
	image->hdr.le_free = (__typeof__(image->hdr.le_free))image_exec_free;
	atomic32_inc(&images);
	return image;
}

/*
 * Must not use config because config will be set to NULL before the last
 * instances of image_exec are drained out of the log queue.
 */
void
image_exec_free(image_exec_t *image) {
	assert(image);
	pthread_mutex_lock(&image->refsmutex);
	image->refs--;
#ifdef DEBUG_REFS
	fprintf(stderr, "DEBUG_REFS: image_exec_free(%p) refs=%zu (was %zu)\n",
	                image, image->refs, image->refs + 1);
#endif
	if (image->refs > 0) {
		pthread_mutex_unlock(&image->refsmutex);
		return;
	}
	pthread_mutex_unlock(&image->refsmutex);
	pthread_mutex_destroy(&image->refsmutex);
	if (image->script)
		image_exec_free(image->script);
	if (image->prev)
		image_exec_free(image->prev);
	if (image->path)
		free(image->path);
	if (image->cwd)
		free(image->cwd);
	if (image->codesign)
		codesign_free(image->codesign);
	atomic32_dec(&images);
	free(image);
}

static void
image_exec_ref(image_exec_t *image) {
	assert(image);
	pthread_mutex_lock(&image->refsmutex);
	image->refs++;
#ifdef DEBUG_REFS
	fprintf(stderr, "DEBUG_REFS: image_exec_ref(%p) refs=%zu (was %zu)\n",
	                image, image->refs, image->refs - 1);
#endif
	pthread_mutex_unlock(&image->refsmutex);
}

/*
 * Prune history of exec images to config->ancestors previous levels.  Go
 * back in history and free previous image iff on the whole path, all images
 * were exclusively owned by this one, i.e. had a refcount of 1, in order to
 * make sure that we are not cutting short another fork's exec history.
 */
static void
image_exec_prune_ancestors(image_exec_t *image, size_t level) {
	assert(image);

#ifdef DEBUG_REFS
	fprintf(stderr, "DEBUG_REFS: image_exec_prune_ancestors(%p, level %zu) "
	                "refs=%zu\n", image, level, image->refs);
#endif
	if (!image->prev)
		return;
	if (level >= config->ancestors) {
		image_exec_free(image->prev);
		image->prev = NULL;
		return;
	}
	if (image->refs == 1)
		image_exec_prune_ancestors(image->prev, level + 1);
}

static int
image_exec_open(image_exec_t *image, const audit_attr_t *attr) {
	char buf[2];
	int rv;

	if (image->flags & (EIFLAG_STAT|EIFLAG_ATTR)) {
#ifdef DEBUG_PROCMON
		fprintf(stderr, "DEBUG_PROCMON: already have stat\n");
#endif
		return 0;
	}

	if (image->flags & EIFLAG_NOPATH) {
		if (attr)
			goto fallback;
		return -1;
	}

	assert(!!strncmp(image->path, "/dev/", 5));
	image->fd = open(image->path, O_RDONLY);
	if (image->fd == -1) {
		if (attr)
			goto fallback;
		return -1;
	}

	rv = sys_fdattr(&image->stat, image->fd);
	if (rv == -1) {
		if (attr)
			goto fallback;
		return -1;
	}

	if (attr && ((image->stat.mode != attr->mode) ||
	             (image->stat.uid != attr->uid) ||
	             (image->stat.gid != attr->gid) ||
	             (image->stat.dev != attr->dev) ||
	             (image->stat.ino != attr->ino)))
		goto fallback;

	/* https://www.in-ulm.de/~mascheck/various/shebang/ */
	if (pread(image->fd, buf, sizeof(buf), 0) == 2)
		if (buf[0] == '#' && buf[1] == '!')
			image->flags |= EIFLAG_SHEBANG;

	image->flags |= EIFLAG_STAT;
#ifdef DEBUG_PROCMON
	fprintf(stderr, "DEBUG_PROCMON: stat from path='%s'\n", image->path);
#endif
	return 0;

fallback:
	image->stat.mode = attr->mode;
	image->stat.uid = attr->uid;
	image->stat.gid = attr->gid;
	image->stat.dev = attr->dev;
	image->stat.ino = attr->ino;
	image->flags |= EIFLAG_ATTR;
	return 0;
}

static void
image_exec_close(image_exec_t *image) {
	assert(image);
	if (image->fd != -1) {
		close(image->fd);
		image->fd = -1;
	}
}

/*
 * kern != 0 indicates that we are currently handling a kernel module callback.
 */
static int
image_exec_analyze(image_exec_t *image, int kern) {
	stat_attr_t st;
	off_t sz;
	bool hit;
	int rv;

	assert(image);

	if (image->flags & EIFLAG_DONE)
		return 0;

	/* postpone hashes for later offline processing */
	if (kern && config->kextlevel < KEXTLEVEL_HASH)
		return 0;

	/* postpone large binaries for later offline processing */
	if (kern && image->stat.size > 1024*1024*8)
		return 0;

	if (!(image->flags & EIFLAG_HASHES)) {
		if (!(image->flags & EIFLAG_STAT) || image->fd == -1) {
			image->flags |= EIFLAG_DONE;
			return -1;
		}

		hit = cachehash_get(&image->hashes,
		                    image->stat.dev,
		                    image->stat.ino,
		                    image->stat.mtime.tv_sec,
		                    image->stat.ctime.tv_sec,
		                    image->stat.btime.tv_sec);
		if (!hit) {
			/* cache miss, calculate hashes */
			rv = hashes_fd(&sz, &image->hashes, config->hflags,
			               image->fd);
			if ((rv == -1) || (sz != image->stat.size)) {
				close(image->fd);
				image->fd = -1;
				image->flags |= EIFLAG_DONE;
				return -1;
			}

			/*
			 * If 2nd stat does not match 1st, invalidate hashes.
			 */
			rv = sys_fdattr(&st, image->fd);
			if (rv == -1) {
				close(image->fd);
				image->fd = -1;
				image->flags |= EIFLAG_DONE;
				return -1;
			}
			/* fd still open, no need to compare dev and ino */
			if ((image->stat.size != st.size) ||
			    (image->stat.mtime.tv_sec != st.mtime.tv_sec) ||
			    (image->stat.mtime.tv_nsec != st.mtime.tv_nsec) ||
			    (image->stat.ctime.tv_sec != st.ctime.tv_sec) ||
			    (image->stat.ctime.tv_nsec != st.ctime.tv_nsec) ||
			    (image->stat.btime.tv_sec != st.btime.tv_sec) ||
			    (image->stat.btime.tv_nsec != st.btime.tv_nsec)) {
				image->flags &= ~EIFLAG_HASHES;
				close(image->fd);
				image->fd = -1;
				image->flags |= EIFLAG_DONE;
				return -1;
			}
			cachehash_put(image->stat.dev,
			              image->stat.ino,
			              image->stat.mtime.tv_sec,
			              image->stat.ctime.tv_sec,
			              image->stat.btime.tv_sec,
			              &image->hashes);
#ifdef DEBUG_PROCMON
			fprintf(stderr, "DEBUG_PROCMON: hashes from path='%s'\n", image->path);
#endif
		}
#ifdef DEBUG_PROCMON
		else
			fprintf(stderr, "DEBUG_PROCMON: hashes from cache\n");
#endif
		image->flags |= EIFLAG_HASHES;
	}
#ifdef DEBUG_PROCMON
	else
		fprintf(stderr, "DEBUG_PROCMON: already have hashes\n");
#endif

	/* everything below operates on paths, not open file descriptors */
	if (image->fd != -1) {
		close(image->fd);
		image->fd = -1;
	}

	/* postpone codesign for later offline processing? */
	if (kern && config->kextlevel < KEXTLEVEL_CSIG) {
		return 0;
	}

	/* skip code signing for scripts */
	if (image->flags & EIFLAG_SHEBANG) {
		image->flags |= EIFLAG_DONE;
		return 0;
	}

#ifdef DEBUG_PROCMON
	if (image->codesign)
		fprintf(stderr, "DEBUG_PROCMON: already have codesign\n");
#endif
	if (!image->codesign && (image->flags & EIFLAG_HASHES)) {
		image->codesign = cachecsig_get(&image->hashes);
		if (!image->codesign) {
			if (errno == ENOMEM) {
				image->flags |= EIFLAG_ENOMEM;
				image->flags |= EIFLAG_DONE;
				return -1;
			}
		}
#ifdef DEBUG_PROCMON
		else
			fprintf(stderr, "DEBUG_PROCMON: codesign from cache\n");
#endif
	}
	if (!image->codesign && config->codesign) {
		/* Postpone codesign verification of processes spawned as part
		 * of codesign verification during KAuth handling. */
		if (kern && (!strcmp(image->path, "/usr/libexec/xpcproxy") ||
		             !strcmp(image->path, "/usr/sbin/ocspd")))
			return 0;

		/* Check code signature (can be very slow!) */
		image->codesign = codesign_new(image->path);
		if (!image->codesign) {
			if (errno == ENOMEM)
				image->flags |= EIFLAG_ENOMEM;
			image->flags |= EIFLAG_DONE;
			return -1;
		}

		/*
		 * If 3rd stat does not match 1st, invalidate codesign.
		 * If 3rd stat fails, return error but don't invalidate anything.
		 * The codesign routines fail internally if the data is changed
		 * during signature verification.
		 */
		rv = sys_pathattr(&st, image->path);
		if (rv == -1) {
			image->flags |= EIFLAG_DONE;
			return -1;
		}
		if ((image->stat.size != st.size) ||
		    (image->stat.dev != st.dev) ||
		    (image->stat.ino != st.ino) ||
		    (image->stat.mtime.tv_sec != st.mtime.tv_sec) ||
		    (image->stat.mtime.tv_nsec != st.mtime.tv_nsec) ||
		    (image->stat.ctime.tv_sec != st.ctime.tv_sec) ||
		    (image->stat.ctime.tv_nsec != st.ctime.tv_nsec) ||
		    (image->stat.btime.tv_sec != st.btime.tv_sec) ||
		    (image->stat.btime.tv_nsec != st.btime.tv_nsec)) {
			codesign_free(image->codesign);
			image->codesign = NULL;
			image->flags |= EIFLAG_DONE;
			return -1;
		}

		cachecsig_put(&image->hashes, image->codesign);
#ifdef DEBUG_PROCMON
		fprintf(stderr, "DEBUG_PROCMON: codesign from path='%s'\n",
		                image->path);
#endif
	}

	image->flags |= EIFLAG_DONE;
	return 0;
}

/*
 * Return true iff the exec event should not be logged (i.e. filtered).
 */
static bool
image_exec_filter(image_exec_t *ei) {
	if (ei->codesign && ei->codesign->ident) {
		/* presence of ident implies that signature is good */
		if (strset_contains(suppress_image_exec_by_ident,
		                    ei->codesign->ident))
			return true;
	}
	if (ei->path) {
		if (strset_contains(suppress_image_exec_by_path, ei->path))
			return true;
	}
	return false;
}

/*
 * Work function to be executed in the worker thread.
 *
 * Returning 0 leads to the event being logged, -1 indicates that this event
 * should not be logged (may or may not be due to an error).
 */
static int
image_exec_work(image_exec_t *ei) {
#ifdef DEBUG_REFS
	fprintf(stderr, "DEBUG_REFS: image_exec_work(%p)\n", ei);
#endif
	image_exec_analyze(ei, 0);
	image_exec_close(ei);
	if (ei->script) {
		image_exec_analyze(ei->script, 0);
		image_exec_close(ei->script);
	}
	if (config->ancestors > 0)
		image_exec_prune_ancestors(ei, 0);
	if (ei->flags & EIFLAG_ENOMEM) {
		atomic64_inc(&ooms);
		return -1;
	}
	if (ei->flags & EIFLAG_NOLOG)
		return -1;
	if (image_exec_filter(ei))
		return -1;
	return 0;
}

/*
 * Create new image_exec from pid using runtime lookups.
 */
static image_exec_t *
image_exec_from_pid(pid_t pid) {
	image_exec_t *ei;
	char *path;
	int nopath = 0;

	path = sys_pidpath(pid);
#ifdef DEBUG_PROCMON
	fprintf(stderr, "DEBUG_PROCMON: image_exec_from_pid(%i) path='%s'\n",
	                pid, path);
#endif
	if (!path) {
		if (errno == ENOMEM) {
			atomic64_inc(&ooms);
			return NULL;
		}
		if (asprintf(&path, "<%i>", pid) == -1) {
			atomic64_inc(&ooms);
			free(path);
			return NULL;
		}
		nopath = 1;
	}
	ei = image_exec_new(path);
	if (!ei)
		return NULL;
	if (nopath)
		ei->flags |= EIFLAG_NOPATH;
	ei->flags |= EIFLAG_PIDLOOKUP;
	ei->pid = pid;
	return ei;
}

/*
 * Create new proc from pid using runtime lookups.
 * Called after looking up the subject of a call fails.
 *
 * Returns NULL on oom or if the process is not running anymore.
 *
 * Does oom counting, caller does not need to.
 * However, caller needs to count and report eimiss if this fails.
 */
static proc_t *
procmon_proc_from_pid(pid_t pid) {
	proc_t *proc;
	pid_t ppid;

	proc = proctab_find_or_create(pid);
	if (!proc) {
		atomic64_inc(&ooms);
		return NULL;
	}

	if (sys_pidbsdinfo(&proc->fork_tv, &ppid,
	                   NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	                   pid) == -1) {
		/* process not alive anymore */
		proctab_remove(pid);
		return NULL;
	}

	if (proc->cwd) {
		free(proc->cwd);
	}
	proc->cwd = sys_pidcwd(pid);
	if (!proc->cwd) {
		if (errno == ENOMEM)
			atomic64_inc(&ooms);
		/* process not alive anymore unless ENOMEM */
		proctab_remove(pid);
		return NULL;
	}

	if (proc->image_exec) {
		image_exec_free(proc->image_exec);
	}
	proc->image_exec = image_exec_from_pid(pid);
	if (!proc->image_exec) {
		/* process not alive anymore unless ENOMEM */
		proctab_remove(pid);
		return NULL;
	}
	image_exec_open(proc->image_exec, NULL);

	/* after acquiring all info from process, go after parent */
	if ((ppid >= 0) && (ppid != pid)) {
		proc_t *pproc = proctab_find(ppid);
		if (!pproc) {
			pproc = procmon_proc_from_pid(ppid);
			if (!pproc) {
				if (errno == ENOMEM) {
					proctab_remove(pid);
					return NULL;
				}
				/* parent not alive anymore */
				ppid = -1;
			}
		}
		if (pproc) {
			proc->image_exec->prev = pproc->image_exec;
			if (proc->image_exec->prev) {
				image_exec_ref(proc->image_exec->prev);
			}
		}
	}

	proc->image_exec->flags |= EIFLAG_NOLOG;
#ifdef DEBUG_REFS
	fprintf(stderr, "DEBUG_REFS: work_submit(%p)\n",
	                proc->image_exec);
#endif
	image_exec_ref(proc->image_exec); /* ref is owned by proc */
	work_submit(proc->image_exec);
	return proc;
}

/*
 * Retrieve the current executable image for a given pid.
 * Intended to be called from other subsystems when logging process context
 * for an event related to a pid.
 * Caller must free the returned image_exec_t with image_exec_free().
 * On error returns NULL.
 * Not thread-safe - must be called from the main thread, not worker or logger!
 *
 * Caller does error counting and reporting.
 */
image_exec_t *
image_exec_by_pid(pid_t pid) {
	proc_t *proc;

	proc = proctab_find(pid);
	if (!proc) {
		proc = procmon_proc_from_pid(pid);
		if (!proc) {
			if (errno != ENOMEM) {
				eimiss_bypid++;
				DEBUG(config->debug, "eimiss_bypid",
				      "pid=%i", pid);
			}
			return NULL;
		}
	}
	image_exec_ref(proc->image_exec);
	return proc->image_exec;
}

/*
 * Handles fork.
 */
void
procmon_fork(struct timespec *tv,
             audit_proc_t *subject, pid_t childpid) {
	proc_t *parent, *child;

#ifdef DEBUG_PROCMON
	fprintf(stderr, "DEBUG_PROCMON: procmon_fork"
	                " subject->pid=%i childpid=%i\n",
	                subject->pid, childpid);
#endif

	parent = proctab_find(subject->pid);
	if (!parent) {
		parent = procmon_proc_from_pid(subject->pid);
		if (!parent) {
			if (errno != ENOMEM) {
				eimiss_forksubj++;
				DEBUG(config->debug, "eimiss_forksubj",
				      "subject.pid=%i childpid=%i",
				      subject->pid, childpid);
			}
			return;
		}
	}
	assert(parent);

	proctab_remove(childpid);
	child = proctab_create(childpid);
	if (!child) {
		atomic64_inc(&ooms);
		return;
	}
	child->fork_tv = *tv;

	assert(parent->cwd);
	child->cwd = strdup(parent->cwd);
	if (!child->cwd) {
		proctab_remove(childpid);
		atomic64_inc(&ooms);
		return;
	}

	assert(parent->image_exec);
	child->image_exec = parent->image_exec;
	image_exec_ref(child->image_exec);
}

/*
 * Only handles true posix_spawn without the POSIX_SPAWN_SETEXEC attribute set.
 * POSIX_SPAWN_SETEXEC is treated as regular exec.
 *
 * Ownership of argv and imagepath is transfered; procmon guarantees that they
 * will be freed.
 */
void
procmon_spawn(struct timespec *tv,
              audit_proc_t *subject,
              pid_t childpid,
              char *imagepath, audit_attr_t *attr,
              char **argv) {
#ifdef DEBUG_PROCMON
	fprintf(stderr, "DEBUG_PROCMON: procmon_spawn"
	                " subject->pid=%i childpid=%i imagepath='%s'\n",
	                subject->pid, childpid, imagepath);
#endif

	procmon_fork(tv, subject, childpid);
	subject->pid = childpid;
	procmon_exec(tv, subject, imagepath, attr, argv);
}


/*
 * For scripts, this will be called once, with argv[0] as the interpreter and
 * argv[1+] as argv[0+] of the script execution, imagepath as the script and
 * attr as the file attributes of the script.
 *
 * Ownership of argv and imagepath is transfered, procmon guarantees that they
 * will be freed.  Only argv and attr can be NULL.
 */
void
procmon_exec(struct timespec *tv,
             audit_proc_t *subject,
             char *imagepath, audit_attr_t *attr,
             char **argv) {
	proc_t *proc;
	image_exec_t *prev_image_exec;
	char *cwd;

#ifdef DEBUG_PROCMON
	fprintf(stderr, "DEBUG_PROCMON: procmon_exec"
	                " subject->pid=%i imagepath='%s'\n",
	                subject->pid, imagepath);
#endif

	proc = proctab_find(subject->pid);
	if (!proc) {
		proc = procmon_proc_from_pid(subject->pid);
		if (!proc) {
			if (errno != ENOMEM) {
				eimiss_execsubj++;
				DEBUG(config->debug, "eimiss_execsubj",
				      "subject.pid=%i imagepath='%s' "
				      "argv[0]='%s'",
				      subject->pid, imagepath,
				      argv ? argv[0] : NULL);
			}
			free(imagepath);
			if (argv)
				free(argv);
			return;
		}
	}
	assert(proc);

	/*
	 * Look up the corresponding exec images acquired by kext events
	 * before the audit event was committed.  Linking the audit event to
	 * the correct kext events even when events are being lost for some
	 * reason is probably the most tricky part of all of this.
	 */
	kqlookups++;
	image_exec_t *image = NULL, *interp = NULL;
	for (tommy_node *node = tommy_list_head(&kqlist);
	     node; node = node->next) {
		image_exec_t *ei = node->data;
		assert(ei);

		/*
		 * Check if image is more recent than the auevent; this can
		 * happen during startup when events get queued up while we are
		 * checking all the running processes.
		 *
		 * Depends on the kernel first performing the vnode KAuth
		 * callback and send the audit event later after the fact.
		 */
		if (timespec_greater(&ei->hdr.tv, tv))
			break;

		if (!image) {
			/*
			 * Find the image based on (pid,dev,ino) or
			 * (pid,basename(path)) as a fallback if no attr is
			 * available from the audit event.  When the kernel
			 * passes a wrong path to the audit framework, it does
			 * not provide attributes; in that case we have to rely
			 * on just the pid and the basename.
			 */
			if (ei->pid == proc->pid &&
			    ((attr && ei->stat.dev == attr->dev &&
			              ei->stat.ino == attr->ino) ||
			     (!attr &&
			      !sys_basenamecmp(ei->path, imagepath)))) {
				/* we have a match */
				tommy_list_remove_existing(&kqlist,
				                           &ei->hdr.node);
				kqsize--;
				image = ei;
				/* script executions always have the
				 * interpreter as argv[0] and the script file
				 * as argv[1].  The remaining arguments are the
				 * arguments passed to the scripts, if any */
				if ((image->flags & EIFLAG_SHEBANG) &&
				    argv && argv[0] && argv[1])
					continue;
				break;
			}
		} else {
			assert(!interp);
			assert(argv && argv[0] && argv[1]);
			/* #! can be relative path and we have no attr now.
			 * Using (pid,basename(path)) is the best we can do
			 * at this point. */
			if (ei->pid == proc->pid &&
			    !sys_basenamecmp(ei->path, argv[0])) {
				/* we have a match */
				tommy_list_remove_existing(&kqlist,
				                           &ei->hdr.node);
				kqsize--;
				interp = ei;
				break;
			}
		}

		kqskips++;
#ifdef DEBUG_PREPQUEUE
		fprintf(stderr, "skipped kqlist for %s[%i] "
		                "while looking for %s[%i]\n",
		                ei->path, ei->pid, imagepath, proc->pid);
#endif
		if (++ei->kqttl == MAXKQTTL) {
			tommy_list_remove_existing(&kqlist,
			                           &ei->hdr.node);
			kqsize--;
			image_exec_free(ei);
			kqtimeouts++;
		}
	}
	assert(!(interp && !image));

#ifdef DEBUG_PROCMON
	if (image)
		fprintf(stderr, "DEBUG_PROCMON: found kext image "
		                "pid=%i path=%s is_script=%i\n",
		                image->pid, image->path,
		                image->flags & EIFLAG_SHEBANG);
	if (interp)
		fprintf(stderr, "DEBUG_PROCMON: found kext interp "
		                "pid=%i path=%s is_script=%i\n",
		                interp->pid, interp->path,
		                interp->flags & EIFLAG_SHEBANG);
#endif

	if (!image) {
		kqnotfounds++;
		image = image_exec_new(imagepath);
		if (!image) {
			/* no counter, oom is the only reason this can happen */
			if (argv)
				free(argv);
			assert(!interp);
			return;
		}
	} else {
		free(imagepath);
	}
	assert(image);
	image_exec_open(image, attr);

	if (image->flags & EIFLAG_SHEBANG) {
		if (!interp) {
			kqnotfounds++;
			if (!argv) {
				eimiss_execinterp++;
				DEBUG(config->debug, "eimiss_execinterp",
				      "subject.pid=%i imagepath='%s' "
				      "argv=NULL",
				      subject->pid, imagepath);
				image_exec_free(image);
				return;
			}
			if (argv[0][0] == '/' || proc->cwd) {
				char *p = sys_realpath(argv[0], proc->cwd);
				if (!p) {
					if (errno == ENOMEM)
						atomic64_inc(&ooms);
					eimiss_execinterp++;
					image_exec_free(image);
					free(argv);
					return;
				}
				interp = image_exec_new(p);
			}
			if (!interp) {
				eimiss_execinterp++;
				DEBUG(config->debug, "eimiss_execinterp",
				      "subject.pid=%i imagepath='%s' "
				      "argv[0]='%s' argv[1]='%s'",
				      subject->pid, imagepath,
				      argv[0], argv[1]);
				image_exec_free(image);
				free(argv);
				return;
			}
		}
		assert(interp);
		image_exec_open(interp, NULL);
	}

	/* replace the process' executable image */
	prev_image_exec = proc->image_exec;
	if (image->flags & EIFLAG_SHEBANG) {
		proc->image_exec = interp;
		proc->image_exec->script = image;
	} else {
		proc->image_exec = image;
	}
	assert(proc->image_exec);
	assert(proc->image_exec != prev_image_exec);
	cwd = strdup(proc->cwd);
	if (!cwd) {
		atomic64_inc(&ooms);
		image_exec_free(proc->image_exec);
		proc->image_exec = NULL;
		/* free what would have been transfered to image_exec below */
		if (prev_image_exec)
			image_exec_free(prev_image_exec);
		if (argv)
			free(argv);
		return;
	}
	assert(proc->image_exec->refs == 1);
	proc->image_exec->hdr.tv = *tv;
	proc->image_exec->fork_tv = proc->fork_tv;
	proc->image_exec->pid = proc->pid;
	proc->image_exec->subject = *subject;
	proc->image_exec->argv = argv;
	proc->image_exec->cwd = cwd;
	proc->image_exec->prev = prev_image_exec;
#ifdef DEBUG_REFS
	fprintf(stderr, "DEBUG_REFS: work_submit(%p)\n",
	                proc->image_exec);
#endif
	image_exec_ref(proc->image_exec); /* ref is owned by proc */
	work_submit(proc->image_exec);
}

/*
 * Called from both EXIT and WAIT4 events because EXIT is only triggered for
 * actual calls to exit(), not for process termination e.g. as a result of
 * signal().  As a result, this routine needs to handle multiple calls per
 * process, ideally with little overhead.  In all cases, the process is already
 * gone and lookups of current process state would be useless here.
 */
void
procmon_exit(pid_t pid) {
#ifdef DEBUG_PROCMON
	fprintf(stderr, "DEBUG_PROCMON: procmon_exit"
	                " pid=%i\n",
	                pid);
#endif

	proctab_remove(pid);
}

/*
 * We use wait4 to catch processes that terminated without calling exit().
 * Because wait4 returns for processes that were terminated as well as for
 * processes that were suspended, we have to check the validity of the pid.
 * If the process does not exist at this time, we remove it from our state.
 *
 * This code requires root privileges.
 */
void
procmon_wait4(pid_t pid) {
	int rv;

#ifdef DEBUG_PROCMON
	fprintf(stderr, "DEBUG_PROCMON: procmon_wait4"
	                " pid=%i\n",
	                pid);
#endif

	if ((pid == -1) || (pid == 0))
		return;

	rv = kill(pid, 0);
	if ((rv == -1) && (errno == ESRCH))
		procmon_exit(pid);
}

/*
 * CWD tracking is only needed in order to reconstruct full paths to relative
 * interpreter paths in shebangs.
 *
 * Path will be freed within procmon and must not be further used by the caller
 * after calling this function.
 */
void
procmon_chdir(pid_t pid, char *path) {
	proc_t *proc;

#ifdef DEBUG_PROCMON
	fprintf(stderr, "DEBUG_PROCMON: procmon_chdir"
	                " pid=%i path='%s'\n",
	                pid, path);
#endif

	proc = proctab_find(pid);
	if (!proc) {
		proc = procmon_proc_from_pid(pid);
		if (!proc) {
			if (errno != ENOMEM) {
				eimiss_chdirsubj++;
				DEBUG(config->debug, "eimiss_chdirsubj",
				      "pid=%i path='%s'", pid, path);
			}
			free(path);
			return;
		}
	}
	assert(proc);

	if (proc->cwd)
		free(proc->cwd);
	proc->cwd = path;
}

/*
 * Called while the kernel is waiting for our KAuth verdict.
 *
 * For scripts, this will be called first for the script, then for the
 * interpreter.
 *
 * Unlike other procmon functions, imagepath will NOT be owned by procmon and
 * remains owned by the caller.
 */
void
procmon_kern_preexec(struct timespec *tm, pid_t pid, const char *imagepath) {
	image_exec_t *ei;
	char *path;

#ifdef DEBUG_PROCMON
	fprintf(stderr, "DEBUG_PROCMON: procmon_kern_preexec"
	                " pid=%i imagepath='%s'\n",
	                pid, imagepath);
#endif

	path = strdup(imagepath);
	if (!path) {
		atomic64_inc(&ooms);
		return;
	}

	ei = image_exec_new(path);
	if (!ei)
		return;
	ei->hdr.tv = *tm;
	ei->pid = pid;
	image_exec_open(ei, NULL);
	image_exec_analyze(ei, 1);
	tommy_list_insert_tail(&kqlist, &ei->hdr.node, ei);
	kqsize++;
}

/*
 * Preload the process context information for pid.
 */
void
procmon_preloadpid(pid_t pid) {
#ifdef DEBUG_PROCMON
	fprintf(stderr, "DEBUG_PROCMON: procmon_preloadpid"
	                " pid=%i\n",
	                pid);
#endif
	/*
	 * The code should actually work without any preloading too.
	 */
	(void)procmon_proc_from_pid(pid);
}

/*
 * Return the stored current working directory for a process by pid.
 */
const char *
procmon_getcwd(pid_t pid) {
	proc_t *proc;

	proc = proctab_find(pid);
	if (!proc) {
		proc = procmon_proc_from_pid(pid);
		if (!proc) {
			if (errno != ENOMEM) {
				eimiss_getcwd++;
				DEBUG(config->debug, "eimiss_getcwd",
				      "pid=%i", pid);
			}
			return NULL;
		}
	}
	return proc->cwd;
}

int
procmon_init(config_t *cfg) {
	proctab_init();
	config = cfg;
	images = 0;
	eimiss_bypid = 0;
	eimiss_forksubj = 0;
	eimiss_execsubj = 0;
	eimiss_execinterp = 0;
	eimiss_chdirsubj = 0;
	eimiss_getcwd = 0;
	ooms = 0;
	kqlookups = 0;
	kqnotfounds = 0;
	kqtimeouts = 0;
	kqskips = 0;
	kqsize = 0;
	tommy_list_init(&kqlist);
	suppress_image_exec_by_ident = &cfg->suppress_image_exec_by_ident;
	suppress_image_exec_by_path = &cfg->suppress_image_exec_by_path;
	return 0;
}

void
procmon_fini(void) {
	if (!config)
		return;

	while (!tommy_list_empty(&kqlist)) {
		image_exec_t *ei;
		ei = tommy_list_remove_existing(&kqlist,
		                                tommy_list_head(&kqlist));
		image_exec_free(ei);
		kqsize--;
	}
	assert(kqsize == 0);
	proctab_fini();
	config = NULL;
}

void
procmon_stats(procmon_stat_t *st) {
	assert(st);

	st->procs = procs; /* external */
	st->images = (uint32_t)images;
	st->eimiss_bypid = eimiss_bypid;
	st->eimiss_forksubj = eimiss_forksubj;
	st->eimiss_execsubj = eimiss_execsubj;
	st->eimiss_execinterp = eimiss_execinterp;
	st->eimiss_chdirsubj = eimiss_chdirsubj;
	st->eimiss_getcwd = eimiss_getcwd;
	st->ooms = (uint64_t)ooms;
	st->kqlookups = kqlookups;
	st->kqnotfounds = kqnotfounds;
	st->kqtimeouts = kqtimeouts;
	st->kqskips = kqskips;
	st->kqsize = kqsize;
}

/*
 * Returns 1 if kextctl events should be handled with priority,
 * 0 if auditpipe events should be handled with priority.
 *
 * MAXKQTTL is the size of the out-of-order arrival window that we tolerate.
 * As long as that window is not full, the kext events should be prioritized
 * in order to avoid processing auditpipe events while we have unprocessed
 * kextctl events.
 */
bool
procmon_kpriority(void) {
	return (kqsize < MAXKQTTL);
}

/*
 * Returns the number of exec images in existence.
 * Can be safely called after procmon_fini().
 */
uint32_t
procmon_images(void) {
	return (uint32_t)images;
}

