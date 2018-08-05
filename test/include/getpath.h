#ifndef TEST_GETPATH_H
#define TEST_GETPATH_H

#include <stdint.h>
#include <stdlib.h>
#include <mach-o/dyld.h>

static inline const char *
getpath(void) {
	char pathbuf[1024];
	uint32_t size = sizeof(pathbuf);
	if (_NSGetExecutablePath(pathbuf, &size) != 0)
		return NULL;
	return realpath(pathbuf, NULL);
}

#endif
