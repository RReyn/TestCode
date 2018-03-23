#ifndef _LOG_H_
#define _LOG_H_

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_LOG_MSG	255

extern void enable_console_log(void);
extern void log_message(const int facility, const char *format, ...);

#ifdef __cplusplus
}
#endif

#endif /* LOG_H END */
