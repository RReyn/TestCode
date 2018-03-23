#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

#include "common.h"
#include "log.h"

static void
process_status_msg(int status, pid_t pid)
{
	if (WIFEXITED(status)) {
		log_message(LOG_INFO, "Process '%d': exit status %d",
				pid, WEXITSTATUS(status));
	} else if (WIFSIGNALED(status)) {
		log_message(LOG_INFO, "Process '%d': killed (%d)",
				pid, WTERMSIG(status));
	} else if (WIFSTOPPED(status)) {
		log_message(LOG_INFO, "Process '%d': stopped (%d)",
				pid, WSTOPSIG(status));
	} else {
		log_message(LOG_INFO, "Process '%d': normal exit (%x)",
				pid, status);
	}
}

static int
should_restart(int status)
{

	if (WIFSIGNALED(status)) {
		size_t i;
		static const int error_signals[] = {
			SIGABRT, SIGALRM, SIGBUS, SIGFPE, SIGKILL,
			SIGILL, SIGPIPE, SIGSEGV, SIGXCPU, SIGXFSZ
		};
		int sig = WTERMSIG(status);

		for (i = 0; i < ARRAY_SIZE(error_signals); i++) {
			if (error_signals[i] == sig)
				return 1;
		}
	}
	return 0;
}

static int
fork_and_wait_for_startup(void)
{
	pid_t pid;
	int retval = 0;
	int status;

	pid = fork();
	if (pid < 0) {
		log_message(LOG_ERR, "Fork error.");
		return -1;
	} else if (pid == 0) {
		/* Child process, exit */
		return 0;
	}

	while (1) {
		do {
			retval = waitpid(pid, &status, 0);	
		} while (retval == -1 && errno == EINTR);

		if (retval == pid) {
			process_status_msg(status, pid);
			if (!should_restart(status))
				continue;
			log_message(LOG_INFO, "Restart daemon process.");
			pid = fork();
			if (pid < 0) {
				log_message(LOG_INFO, "Fork error.");
			} else if (pid == 0) {
				log_message(LOG_INFO, "child process, running...");	
				return 0;
			}
		}
	}
	return 0;
}

int
rte_daemon(void)
{
	if (daemon(0, 0)) {
		log_message(LOG_ERR, "Daemon start failed.");
		return -1;
	}

	if (fork_and_wait_for_startup()) {
		log_message(LOG_ERR, "Failed to initiate process monitoring.");
		return -1;
	} 

	return 0;
}
