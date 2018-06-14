#include <unistd.h>
#include <stdio.h>

int
main(int argc, char *argv[]) {
	printf("%i exec /usr/bin/true\n", getpid());

	char *cargv[2] = {"true", 0};
	char *cenv[1] = {0};
	execve("/usr/bin/true", cargv, cenv);
	perror("execve");
	return 1;
}

