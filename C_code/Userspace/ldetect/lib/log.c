#include <stdarg.h>

#include "common.h"
#include "lib/log.h"

/* Boolen flag - send messages to console as well as syslog */
static int log_console = 0;

void
enable_console_log(void)
{
	log_console = 1;
}

static void
vlog_message(const int facility, const char *format, va_list args)
{
	char buf[MAX_LOG_MSG + 1];

	vsnprintf(buf, sizeof(buf), format, args);

	if (log_console)
		fprintf(stderr, "%s\n", buf);
	syslog(facility, "%s", buf);
}

void
log_message(const int facility, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vlog_message(facility, format, args);
	va_end(args);
}

