#ifndef _FLB_H_
#define _FLB_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CONFIG_64BIT
#define BITS_PER_LONG	64
#else
#define BITS_PER_LONG	32
#endif /* CONFIG_64BIT */

extern unsigned long find_last_bit(const unsigned long *addr, unsigned long size);

#ifdef __cplusplus
}
#endif

#endif /* FLB_H END */
