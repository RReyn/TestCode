#include <assert.h>
#include <fcntl.h>

#include "common.h"
#include "log.h"

#define FILE_MODE	S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH

/*
 * pidfile_write: create the running daemon pidfile, write @pid to @pid_file
 * return:
 *	true:	success
 *	false:	error
 */
bool
pidfile_write(const char *pid_file, int pid)
{
	FILE *pidfile = NULL;
	int pidfd;

	assert(pid_file != NULL);

	pidfd = creat(pid_file, FILE_MODE);
	if (pidfd != -1) {
		pidfile = fdopen(pidfd, "w");
	}

	if (!pidfile) {
		log_message(LOG_INFO, "pidfile_write: cannot open %s pidfile",
				pid_file);
		return false;
	}
	fprintf(pidfile, "%d\n", pid);
	fclose(pidfile);

	return true;
}

/*
 * pidfile_rm: remove the running daemon pidfile @pid_file 
 */
void
pidfile_rm(const char *pid_file)
{
	unlink(pid_file);
}

/*
 * process_running: check the process recorded in @pid_file is running or not
 * return:
 *	true:	running
 *	false:	not running
 */
static bool 
_process_running(const char *pid_file)
{
	FILE *pidfile = NULL;
	pid_t pid = 0;
	int ret = 0;

	pidfile = fopen(pid_file, "r");
	/* No pid_file */
	if (pidfile == NULL) {
		return false;
	}

	ret = fscanf(pidfile, "%d", &pid);
	fclose(pidfile);
	if (ret != 1) {
		pid = 0;
		pidfile_rm(pid_file);
	}
	/* What should we return - we don't know if it is running or not*/
	if (pid == 0) {
		return true;
	}

	/* If no process is attached to pidfile, remove it  */
	if (kill(pid, 0)) {
		log_message(LOG_INFO, "Remove a zombie pid file '%s'", pid_file);
		pidfile_rm(pid_file);
		return false;
	}

	return true;
}

/*
 * Return parent process daemon state
 */
bool
process_running(const char *pid_file)
{
	assert(pid_file != NULL);
	return _process_running(pid_file);
}

