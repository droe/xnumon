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
 * File monitoring core.
 *
 * Complexity comes from tracking hardlinks and symlinks properly, to catch
 * changes outside of the monitored directories, which through indirections
 * like hardlinks or symlinks constitute an effective change within a monitored
 * directory, without any actual changes within the monitored directory.
 *
 * Due to the complexity, no attempt is made to track directory symlinks or
 * hardlinks affecting effective contents of monitored path prefixes.  Instead,
 * regular scans of the monitored directories are performed in order to catch
 * modifications that were missed.  Those still trigger events, but cannot be
 * linked to the process or executable image that performed the file operation.
 */

#include "filemon.h"

#include "work.h"
#include "str.h"
#include "cf.h"
#include "cacheldpl.h"
#include "atomic.h"
#include "tommyhashdyn.h"
#include "tommylist.h"
#include "minmax.h"

#include <sys/stat.h>
#include <stdlib.h>
#include <stdbool.h>
#include <strings.h>
#include <fcntl.h>
#include <glob.h>
#include <paths.h>
#include <assert.h>

static config_t *config;

static uint64_t events_recvd;       /* number of filesystem events received */
static uint64_t events_procd;       /* number of filesystem events processed */
static atomic64_t ooms;             /* counts events impaired due to OOM */
static atomic64_t lpmiss;           /* plists that were not present anymore */

static void filemon_launchd_touched(struct timespec *, audit_proc_t *, char *);
static bool filemon_is_launchd_path(const char *);

/*
 * Symlinks tracking for launchd add
 */

static tommy_hashdyn symlinks;
static tommy_list symlinks_dangling; /* subset of symlinks */

typedef struct symlinks_obj {
	tommy_hashdyn_node h_node;
	tommy_node l_node;
	char *path;

	/*
	 * Object is in one of three states at all times:
	 * a) is_regular_file == false, target == NULL, in symlinks_dangling
	 * b) is_regular_file == false, target != NULL, in target->origins
	 * c) is_regular_file == true, target == NULL, not in any list
	 */
	bool is_regular_file;
	tommy_list origins;
	struct symlinks_obj *target;
} symlinks_obj_t;

static symlinks_obj_t *
symlinks_obj_new(char *path) {
	symlinks_obj_t *obj;

	obj = malloc(sizeof(symlinks_obj_t));
	if (!obj)
		return NULL;
	bzero(obj, sizeof(symlinks_obj_t));
	obj->path = path;
	tommy_list_init(&obj->origins);
	return obj;
}

static void
symlinks_obj_free(void *arg) {
	symlinks_obj_t *obj = arg;
	free(obj->path);
	free(obj);
}

static int
symlinks_obj_cmp(const void *path, const void* obj) {
	return strcmp(((const symlinks_obj_t*)obj)->path, path);
}

static void
symlinks_init(void) {
	tommy_hashdyn_init(&symlinks);
	tommy_list_init(&symlinks_dangling);
}

static void
symlinks_fini(void) {
	tommy_hashdyn_foreach(&symlinks, symlinks_obj_free);
	tommy_hashdyn_done(&symlinks);
}

static symlinks_obj_t *
symlinks_path_find(const char *path) {
	return tommy_hashdyn_search(&symlinks, symlinks_obj_cmp, path,
	                            tommy_strhash_u32(0, path));
}

#define symlinks_path_is_relevant(P) ((bool)symlinks_path_find(P))

/*
 * If origin != NULL, indicates the origin that is being removed and therefore
 * wants to unreference obj.  If origin == NULL, this is a direct unlink from
 * an event.
 */
static void
symlinks_obj_unref(symlinks_obj_t *obj, symlinks_obj_t *origin) {
	if (origin) {
		origin->target = NULL;
		tommy_list_remove_existing(&obj->origins, &origin->l_node);
		tommy_list_insert_head(&symlinks_dangling,
		                       &origin->l_node, origin);
	}
	if (!tommy_list_empty(&obj->origins))
		return;

	/* this node needs to be removed, no origins point to this anymore */
	if (obj->target) {
		symlinks_obj_unref(obj->target, obj);
	}
	tommy_hashdyn_remove_existing(&symlinks, &obj->h_node);
	if (!obj->is_regular_file) {
		tommy_list_remove_existing(&symlinks_dangling, &obj->l_node);
	}
	symlinks_obj_free(obj);
}

/*
 * Copies path.
 */
static symlinks_obj_t *
symlinks_path_add(const char *path, symlinks_obj_t *origin) {
	symlinks_obj_t *obj;

	tommy_hash_t h;
	h = tommy_strhash_u32(0, path);
	obj = tommy_hashdyn_search(&symlinks, symlinks_obj_cmp, path, h);
	if (!obj) {
		obj = symlinks_obj_new(strdup(path));
		if (!obj)
			return NULL;
		tommy_hashdyn_insert(&symlinks, &obj->h_node, obj, h);
		tommy_list_insert_head(&symlinks_dangling, &obj->l_node, obj);
	}
	assert(obj);
	if (origin && (origin->target == NULL)) {
		origin->target = obj;
		if (origin->is_regular_file) {
			origin->is_regular_file = false;
		} else {
			tommy_list_remove_existing(&symlinks_dangling,
			                           &origin->l_node);
		}
		tommy_list_insert_head(&obj->origins, &origin->l_node, origin);
	}
	return obj;
}

static void
symlinks_path_walk(const char *path,
                   struct timespec *tv, audit_proc_t *subject) {
	symlinks_obj_t *obj, *root;
	char *target, *rtarget;

	root = obj = symlinks_path_add(path, NULL);
	assert(obj);
	rtarget = strdup(path);
	if (!rtarget) {
		ooms++;
		return;
	}
	while (rtarget) {
		target = sys_readlink(rtarget);
		free(rtarget);
		if (!target)
			break;
		rtarget = sys_realdir(target, "/");
		if (!rtarget) {
			/* directory part may not exist, add unresolved */
			obj = symlinks_path_add(target, obj);
			free(target);
			break;
		}
		free(target);
		obj = symlinks_path_add(rtarget, obj);
	}

	if (!obj->is_regular_file && sys_islnk(obj->path) != 1) {
		if (obj->target)
			symlinks_obj_unref(obj->target, obj);
		tommy_list_remove_existing(&symlinks_dangling, &obj->l_node);
		obj->is_regular_file = true;
	}

	if (!tv)
		return;

	assert(root);
	/* walk up to the actual root for logging */
	while (!tommy_list_empty(&root->origins)) {
		root = tommy_list_head(&root->origins)->data;
	}
	if (!filemon_is_launchd_path(root->path) &&
	    !tommy_list_empty(&symlinks_dangling)) {
		/* limit aggressively */
		size_t n = min(tommy_list_count(&symlinks_dangling),
		               (size_t)16);
		char *paths[n];
		char **pp = paths;
		tommy_node *dsl = tommy_list_head(&symlinks_dangling);
		while (dsl) {
			symlinks_obj_t *dslobj = dsl->data;
			*(pp++) = dslobj->path;
			dsl = dsl->next;
		}
		for (size_t i = 0; i < n; i++) {
			symlinks_path_walk(paths[i], NULL, NULL);
		}
	}
	filemon_launchd_touched(tv, subject, strdup(root->path));
}

static void
symlinks_path_remove(const char *path) {
	symlinks_obj_t * obj;

	obj = symlinks_path_find(path);
	if (!obj)
		return;
	symlinks_obj_unref(obj, NULL);
}

static bool
filemon_is_launchd_path(const char *path) {
	const char *p;

	assert(path);
	if (path[0] != '/')
		return false;
	if (str_beginswith(path, "/System/Library/LaunchDaemons/"))
		return true;
	if (str_beginswith(path, "/Library/LaunchDaemons/"))
		return true;
	if (str_beginswith(path, "/System/Library/LaunchAgents/"))
		return true;
	if (str_beginswith(path, "/Library/LaunchAgents/"))
		return true;
	if (!str_beginswith(path, "/Users/"))
		return false;
	p = path + 7;
	while (*p != '/') {
		if (!*p)
			return false;
		p++;
	}
	if (!str_beginswith(p, "/Library/LaunchAgents/"))
		return false;
	return true;
}

static void launchd_add_free(launchd_add_t *);
static int launchd_add_work(launchd_add_t *);

/*
 * Always frees path regardless of success.
 */
static launchd_add_t *
launchd_add_new(char *path) {
	launchd_add_t *ldadd;

	ldadd = malloc(sizeof(*ldadd));
	if (!ldadd) {
		free(path);
		return NULL;
	}
	bzero(ldadd, sizeof(*ldadd));
	ldadd->plist_path = path;
	ldadd->hdr.code = LOGEVT_LAUNCHD_ADD;
	ldadd->hdr.le_work = (__typeof__(ldadd->hdr.le_work))launchd_add_work;
	ldadd->hdr.le_free = (__typeof__(ldadd->hdr.le_free))launchd_add_free;
	return ldadd;
}

static void
launchd_add_free(launchd_add_t *ldadd) {
	if (ldadd->program_rpath)
		free(ldadd->program_rpath);
	if (ldadd->program_path)
		free(ldadd->program_path);
	if (ldadd->program_argv)
		free(ldadd->program_argv);
	if (ldadd->subject_image_exec)
		image_exec_free(ldadd->subject_image_exec);
	free(ldadd->plist_path);
	free(ldadd);
}

static int
launchd_add_open(launchd_add_t *ldadd) {
	ldadd->plist_fd = open(ldadd->plist_path, O_RDONLY);
	if (ldadd->plist_fd == -1) {
		atomic64_inc(&lpmiss);
		return -1;
	}
	return sys_fdattr(&ldadd->plist_stat, ldadd->plist_fd);
}

static void
launchd_add_acquire(launchd_add_t *ldadd) {
	CFPropertyListRef plist;

	assert(ldadd->plist_path);
	plist = cf_plist_load(ldadd->plist_path);
	if (!plist) {
		atomic64_inc(&lpmiss);
		return;
	}
	ldadd->program_path = cf_cstr(CFDictionaryGetValue(
	                      (CFDictionaryRef)plist,
	                      CFSTR("Program")));
	if (!ldadd->program_path && (errno == ENOMEM)) {
		atomic64_inc(&ooms);
		CFRelease(plist);
		return;
	}
	ldadd->program_argv = cf_aev(CFDictionaryGetValue(
	                      (CFDictionaryRef)plist,
	                      CFSTR("ProgramArguments")));
	if (!ldadd->program_argv && (errno == ENOMEM)) {
		atomic64_inc(&ooms);
		CFRelease(plist);
		return;
	}
	CFRelease(plist);

	if (ldadd->program_path) {
		ldadd->program_rpath = sys_realpath(ldadd->program_path, NULL);
	} else if (ldadd->program_argv && ldadd->program_argv[0]) {
		if (ldadd->program_argv[0][0] == '/') {
			/* absolute path */
			ldadd->program_rpath =
				sys_realpath(ldadd->program_argv[0], NULL);
		} else if (!!strchr(ldadd->program_argv[0], '/')) {
			/* relative path */
			ldadd->program_rpath =
				sys_realpath(ldadd->program_argv[0], "/");
		} else {
			/* filename to be searched in PATH */
			ldadd->program_rpath = sys_which(ldadd->program_argv[0],
			                                _PATH_STDPATH);
			ldadd->program_rpath =
				sys_realpath(ldadd->program_rpath, NULL);
		}
	}
	if (!ldadd->program_path && (errno == ENOMEM))
		atomic64_inc(&ooms);

	/*
	 * For now, we are deliberatly not obtaining hashes and codesign status
	 * for the binary that ldadd->program_path points to.  There should be
	 * an eventid==3 event shortly after the eventid==4 event which will
	 * deliver exactly that information.
	 */
}

static void
launchd_add_close(launchd_add_t *ldadd) {
	if (ldadd->plist_fd != -1)
		close(ldadd->plist_fd);
}

static int
launchd_add_work(launchd_add_t *ldadd) {
	launchd_add_acquire(ldadd);
	launchd_add_close(ldadd);
	return 0;
}

static void
filemon_launchd_touched(struct timespec *tv, audit_proc_t *subject,
                        char *path) {
	launchd_add_t *ldadd;
	bool hit;

	ldadd = launchd_add_new(path);
	if (!ldadd) {
		atomic64_inc(&ooms);
		return;
	}
	if (launchd_add_open(ldadd) == -1) {
		launchd_add_free(ldadd);
		return;
	}
	hit = cacheldpl_get(ldadd->plist_stat.dev,
	                    ldadd->plist_stat.ino,
	                    ldadd->plist_stat.mtime.tv_sec,
	                    ldadd->plist_stat.ctime.tv_sec,
	                    ldadd->plist_stat.btime.tv_sec);
	if (hit) {
		launchd_add_close(ldadd);
		launchd_add_free(ldadd);
		return;
	}
	cacheldpl_put(ldadd->plist_stat.dev,
	              ldadd->plist_stat.ino,
	              ldadd->plist_stat.mtime.tv_sec,
	              ldadd->plist_stat.ctime.tv_sec,
	              ldadd->plist_stat.btime.tv_sec);
	ldadd->subject_image_exec = image_exec_by_pid(subject->pid, tv);
	if (ldadd->subject_image_exec && (
	        (ldadd->subject_image_exec->pid == 1) ||
	        (ldadd->subject_image_exec->path &&
	         str_beginswith(ldadd->subject_image_exec->path,
	                   "/System/Library/Frameworks/CoreServices.framework"
	                   "/Versions/A/Frameworks/Metadata.framework"
	                   "/Versions/A/Support/md")))) {
		/*
		 * mdworker touches newly written files, launchd opens plists
		 * when they are loaded.  If they are showing up here, it is
		 * because of an AUE_CLOSE event on a file that was written by
		 * a previous syscall from another process, whose audit
		 * event was missed for some reason, e.g. one of the
		 * many audit(4) bugs, such as radar 42770257.
		 * Blank the subject to prevent misidentifications.
		 */
		image_exec_free(ldadd->subject_image_exec);
		ldadd->subject_image_exec = NULL;
		ldadd->flags |= LAFLAG_NOSUBJECT;
	} else {
		ldadd->subject = *subject;
	}
	ldadd->hdr.tv = *tv;
	work_submit(ldadd);
}

/*
 * Called for all file close, rename etc events with path to the potentially
 * changed file.  Guarantees path to be freed regardless of outcome.
 *
 * Assumes that path is an absolute and fully resolved path to a real file, not
 * a symlink.  However, path may or may not be a hard link.
 */
void
filemon_touched(struct timespec *tv, audit_proc_t *subject, char *path) {
	events_recvd++;
	if (symlinks_path_is_relevant(path) || filemon_is_launchd_path(path)) {
		events_procd++;
		filemon_launchd_touched(tv, subject, path);
		return;
	}
	free(path);
}

/*
 * Called for unlink() with path to the unlinked file or directory.
 * Path is not freed.
 */
void
filemon_unlink(const char *path, audit_attr_t *attr) {
	events_recvd++;

	if (attr) {
		if (!S_ISLNK(attr->mode))
			return;
	} else {
		if (sys_islnk(path) == 1)
			return;
	}

	if (symlinks_path_is_relevant(path)) {
		events_procd++;
		symlinks_path_remove(path);
	}
}

/*
 * Called for symlink creation with path to the created symlink.
 * Guarantees path to be freed regardless of outcome.
 *
 * Assumes that path points to a symlink and that all directory components are
 * fully resolved.
 */
void
filemon_symlink(struct timespec *tv, audit_proc_t *subject, char *path) {
	events_recvd++;
	if (symlinks_path_is_relevant(path) || filemon_is_launchd_path(path)) {
		events_procd++;
		symlinks_path_walk(path, tv, subject);
	}
	free(path);
}

/*
 * Add a single plist file to the launchd plist file cache; used as callback
 * for sys_dir_eachfile().
 */
static int
filemon_init_add_plist(const char *path, UNUSED void *udata) {
	stat_attr_t st;
	int rv;

	rv = sys_pathattr(&st, path);
	if (rv == -1)
		return 0;
	cacheldpl_put(st.dev,
	              st.ino,
	              st.mtime.tv_sec,
	              st.ctime.tv_sec,
	              st.btime.tv_sec);
	if (sys_islnk(path) == 1)
		symlinks_path_walk(path, NULL, NULL);
	return 0;
}

/*
 * Initialize the file monitor and add all the existing plist files to the
 * plist file cache.  We accept that there is a race condition here in that
 * plists added while xnumon is initializing may be missed and end up not added
 * to the cache.  When that happens, a later read on the plist will be handled
 * as if it were a write, essentially just delaying detection.
 */
int
filemon_init(config_t *cfg) {
	config = cfg;
	ooms = 0;
	lpmiss = 0;
	events_recvd = 0;
	events_procd = 0;
	glob_t g;

	symlinks_init();

	(void)sys_dir_eachfile_l("/System/Library/LaunchDaemons/",
	                         filemon_init_add_plist, NULL);
	(void)sys_dir_eachfile_l("/Library/LaunchDaemons/",
	                         filemon_init_add_plist, NULL);
	(void)sys_dir_eachfile_l("/System/Library/LaunchAgents/",
	                         filemon_init_add_plist, NULL);
	(void)sys_dir_eachfile_l("/Library/LaunchAgents/",
	                         filemon_init_add_plist, NULL);
	bzero(&g, sizeof(g));
	glob("/Users/*/Library/LaunchAgents/", 0, NULL, &g);
	for (int i = 0; i < g.gl_matchc; i++) {
		(void)sys_dir_eachfile_l(g.gl_pathv[i],
		                         filemon_init_add_plist, NULL);
	}

	return 0;
}

void
filemon_fini(void) {
	if (!config)
		return;
	symlinks_fini();
	config = NULL;
}

void
filemon_stats(filemon_stat_t *st) {
	assert(st);

	st->recvd = events_recvd;
	st->procd = events_procd;
	st->lpmiss = (uint64_t)lpmiss;
	st->ooms = (uint64_t)ooms;
}

