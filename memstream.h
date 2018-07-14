#if defined(__linux__)
# include <features.h>
#endif
#if defined(__APPLE__)
# include <Availability.h>
# if __MAC_OS_X_VERSION_MAX_ALLOWED < 101300
#  define WANT_MEMSTREAM
# endif
#else
# if _POSIX_C_SOURCE < 200809L
#  define WANT_MEMSTREAM
# endif
#endif

#include <stdio.h>

#ifdef WANT_MEMSTREAM

FILE *open_memstream(char **ptr, size_t *sizeloc);

#endif /* WANT_MEMSTREAM */
