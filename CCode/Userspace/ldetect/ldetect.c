#ifdef DEBUG
#include <mcheck.h>
#endif

#include "common.h"
#include "thread.h"
#include "ld_config.h"
#include "pidfile.h"
#include "daemon.h"
#include "backtrace.h"
#include "ld_recv.h"
#include "ld_report.h"
#include "ld_send.h"
#include "log.h"

#define LDETECT_PIDFILE		"/var/run/ldetectd.pid"

static void
ldetect_cleanup(void)
{
	pidfile_rm(LDETECT_PIDFILE);
}

static void
start_ldetectd(void)
{
	/* initial receive  thread */
	recv_thread_init();	
	/* initial report status thread */
	ldetect_report_status();
	/* initial every detect list a thread */
	detect_list_init();
}

int
main(int argc, char *argv[])
{
	thread_t thread;

#ifdef DEBUG
	/* check memory leak */
	mtrace();
#endif
	rte_backtrace_init();

	if (process_running(LDETECT_PIDFILE)) {
		log_message(LOG_ERR, "Ldetect daemon is already running.");
		exit(1);
	}
	if (rte_daemon() != 0) {
		exit(1);
	}

	atexit(ldetect_cleanup);

	if (!pidfile_write(LDETECT_PIDFILE, getpid())) {
		exit(1);
	}

	master = thread_make_master();
	if (!master) {
		log_message(LOG_ERR, "Master is NULL.");
		exit(1);
	}

	if (ldetect_init() != 0) {
		exit(1);
	}

	start_ldetectd();

	while (thread_fetch(master, &thread))
		thread_call(&thread);

	return 0;
}
