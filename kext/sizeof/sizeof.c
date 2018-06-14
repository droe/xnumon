#define KERNEL 1
#define KERNEL_PRIVATE 1
#include <sys/param.h>  /* MAXPATHLEN */
#include <sys/select.h> /* struct selinfo */
#undef KERNEL_PRIVATE
#undef KERNEL

#include <stdio.h>

int
main(int argc, char *argv[]) {
	printf("MAXPATHLEN == %zu\n", (size_t)MAXPATHLEN);
	printf("sizeof(struct selinfo) == %zu\n", sizeof(struct selinfo));
	return 0;
}

