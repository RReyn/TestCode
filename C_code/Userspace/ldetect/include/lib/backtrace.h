#ifndef _BACKTRACE_H_
#define _BACKTRACE_H_

#ifdef __cplusplus
extern "c" {
#endif

#define MAX_BT_SIZE	32
#define BACKTRACE_FILE	"/var/log/backtrace.log"

/* signal and signal handler function */
struct sig_handler {
	int signal;
	void (*func)(int);
};

extern int rte_backtrace_init(void);

#ifdef __cplusplus
}
#endif

#endif /* BACKTRACE_H END */
