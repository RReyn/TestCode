#ifndef _PIDFILE_H_
#define _PIDFILE_H_

#ifdef __cplusplus
extern "C" {
#endif

extern bool pidfile_write(const char *pidfile, int pid);
extern void pidfile_rm(const char *pidfile);
extern bool process_running(const char *pidfile);

#ifdef __cplusplus
}
#endif

#endif /* PIDFILE_H END */
