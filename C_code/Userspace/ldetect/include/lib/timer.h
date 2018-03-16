#ifndef _TIMER_H_
#define _TIMER_H_

#include <sys/time.h>
#include <limits.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct timeval timeval_t;

/* Global vars */
extern timeval_t time_now;

/* Some defines */
#define TIME_MAX_FORWARD_US	2000000U
#define TIMER_HZ		1000000U
#define TIMER_CENTI_HZ		10000U
#define TIMER_MAX_SEC		1000U
#define TIMER_NEVER		ULONG_MAX

/* Some usefull macros */
#define timer_sec(T) ((T).tv_sec)
#define timer_long(T) (unsigned long)(((T).tv_sec * TIMER_HZ + (T).tv_usec))
#define timer_isnull(T) ((T).tv_sec == 0 && (T).tv_usec == 0)
#define timer_reset(T) (memset(&(T), 0, sizeof(timeval_t)))
/* call this instead of timer_reset() when you intend to set
 * all the fields of timeval manually afterwards. */
#define timer_reset_lazy(T) do { \
	if ( sizeof((T)) != sizeof((T).tv_sec) + sizeof((T).tv_usec) ) \
		timer_reset((T)); \
	} while (0)

/* prototypes */
extern timeval_t timer_now(void);
extern timeval_t set_time_now(void);
extern timeval_t timer_dup(timeval_t);
extern int timer_cmp(timeval_t, timeval_t);
extern timeval_t timer_sub(timeval_t, timeval_t);
extern timeval_t timer_add(timeval_t, timeval_t);
extern timeval_t timer_add_long(timeval_t, unsigned long);
extern timeval_t timer_sub_now(timeval_t);
extern timeval_t timer_add_now(timeval_t);
extern unsigned long timer_tol(timeval_t);
#ifdef _INCLUDE_UNUSED_CODE_
extern void timer_dump(timeval_t);
#endif

#ifdef __cplusplus
}
#endif

#endif /* TIMER_H END */
