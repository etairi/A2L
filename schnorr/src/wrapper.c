#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
	pid_t alice, bob, tumbler;

	tumbler = fork();
	if (tumbler == 0) {
		char *args[] = { "./tumbler", NULL };
		char *env[] = { NULL };
		execve("./tumbler", args, env);
		_exit(1);
	} else if (tumbler == -1) {
		fprintf(stderr, "Error: failed to fork Tumbler.\n");
		exit(1);
	}

	alice = fork();
	if (alice == 0) {
		char *args[] = { "./alice", NULL };
		char *env[] = { NULL };
		execve("./alice", args, env);
		_exit(1);
	} else if (alice == -1) {
		fprintf(stderr, "Error: failed to fork Alice.\n");
		exit(1);
	}

	bob = fork();
	if (bob == -1) {
		fprintf(stderr, "Error: failed to fork Bob.\n");
		exit(1);
	} else if (bob > 0) {
		int status;
		waitpid(bob, &status, 0);
		kill(tumbler, SIGINT);
	} else {
		char *args[] = { "./bob", NULL };
		char *env[] = { NULL };
		execve("./bob", args, env);
		_exit(1);
	}

	return 0;
}