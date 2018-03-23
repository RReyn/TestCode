#ifndef _COMPILE_H_
#define _COMPILE_H_

#ifdef __cplusplus
extern "C" {
#endif

#define __compiler_offsetof(a, b)	__builtin_offsetof(a, b)
#define UNUSED	__attribute__((__unused__))

#undef likely
#define likely(x)	__builtin_expect(!!(x), 1)
#undef unlikely
#define unlikely(x)	__builtin_expect(!!(x), 0)


#ifdef __cplusplus
}
#endif

#endif /* COMPILE_H END*/
