#include <sys/time.h>
#include <execinfo.h>
#include <time.h>

#include "common.h"
#include "backtrace.h"

static void
rte_dump_backtrace(int sig)
{
	size_t i;
	FILE *fp = NULL;
	void *bt[MAX_BT_SIZE];
	size_t bt_size;
	char **bt_sym;
	time_t now;
	struct tm tm;
	struct timeval tv;

	time(&now);
	gettimeofday(&tv, NULL);
	gmtime_r(&now, &tm);

	fp = fopen(BACKTRACE_FILE, "a+");
	if (fp == NULL) {
		return;
	}

	bt_size = backtrace(bt, MAX_BT_SIZE);
	bt_sym = backtrace_symbols(bt, bt_size);

	fprintf(fp, "[%d-%d-%d %d:%d:%d] BUG: Program received signal '%d', exited\n",
			tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
			tm.tm_hour, tm.tm_min, tm.tm_sec, sig);
	fprintf(fp, "Call Trace:\n");

	for (i = 0; i < bt_size; i++) {
		fprintf(fp, "%p: %s\n", bt[i], bt_sym[i]);
	}
	fprintf(fp, "--------[ END Trace]--------\n\n");
	free(bt_sym);
	fclose(fp);

	return;
}

static void
rte_signal_handler(int sig)
{
	struct sigaction action;

	rte_dump_backtrace(sig);

	action.sa_handler = SIG_DFL;
	sigemptyset(&action.sa_mask);
	action.sa_flags = 0;
	sigaction(sig, &action, NULL);
	raise(sig);

	return;
}

static struct sig_handler sig_handlers[] = {
	{SIGINT, rte_signal_handler},
	{SIGSEGV, rte_signal_handler},
	{SIGPIPE, rte_signal_handler},
	{SIGBUS, rte_signal_handler},
	{SIGILL, rte_signal_handler},
	{SIGFPE, rte_signal_handler},
	{SIGABRT, rte_signal_handler}
};

static int
rte_signal_set(int sig, void (*func)(int))
{
	int ret = 0;
	struct sigaction action;

	action.sa_handler = func;
	sigemptyset(&action.sa_mask);
	action.sa_flags = 0;

	ret = sigaction(sig, &action, NULL);
	if (ret < 0)
		return -1;
	return 0;
}

static int
rte_signal_register(struct sig_handler *handler, unsigned int n)
{
	unsigned int i = 0;

	for (i = 0; i < n; i++) {
		if (rte_signal_set(handler[i].signal,
					handler[i].func) != 0) {
			return -1;
		}
	}

	return 0;
}

int
rte_backtrace_init(void)
{
	return rte_signal_register(sig_handlers, ARRAY_SIZE(sig_handlers));
}
