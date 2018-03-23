#ifndef _COMMON_H_
#define _COMMON_H_

/* system include */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#include <sys/types.h>
#include <stdbool.h>
#include <sys/stat.h>

#include "compile.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ARRAY_SIZE(x)	(sizeof(x) / sizeof((x)[0]))

#ifndef FREE
#define FREE(x)			\
	if (x) {		\
		free(x);	\
		(x) = NULL;	\
	}
#endif

#undef offsetof
#ifdef __compiler_offsetof
#define offsetof(TYPE, MEMBER)	__compiler_offsetof(TYPE, MEMBER)
#else
#define offsetof(TYPE, MEMBER)	((size_t)&((TYPE *)0)->MEMBER)
#endif

#define container_of(ptr, type, member) ({				\
		const typeof (((type *)0)->member) *__mptr = (ptr);	\
		(type *)((char *)__mptr - offsetof(type, member));	\
	})

/* Macro to return the mininum or maximum of two numbers */
#define MIN(a, b)	({		\
		typeof (a) _a = (a);	\
		typeof (b) _b = (b);	\
		_a < _b ? _a : _b;	\
	})
#define MAX(a,b)	({		\
		typeof (a) _a = (a);	\
		typeof (b) _b = (b);	\
		_a > _b ? _a : _b;	\
	})

#ifdef __cplusplus
}
#endif

#endif /* COMMON_H END */
