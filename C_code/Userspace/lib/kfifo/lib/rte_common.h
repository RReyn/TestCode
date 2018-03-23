#ifndef __COMMON_H__
#define __COMMON_H__

#ifdef __cplusplus
extern "C" {
#endif

#define __must_check	__attribute__((warn_unused_result))

/*
 * Macro to return the minimum of two numbers
 */
#define min(a, b) ({ \
		typeof (a) _a = (a); \
		typeof (b) _b = (b); \
		_a < _b ? _a : _b; \
	})

#define max(a, b) ({ \
		typeof (a) _a = (a); \
		typeof (b) _b = (b); \
		_a > _b ? _a : _b; \
	})

/* Memory barrier: FULL barrier */
#ifdef __KERNEL__ 
#define mb() __asm__ __volatile__("": : :"memory")
#else
#define mb()	__sync_synchronize()
#endif

#define ARRAY_SIZE(x) ((sizeof(x)) / (sizeof((x)[0])))


/**
 * Returns true if n is a power of 2
 * @param n
 * 	Number to check
 *
 * @return
 * 	1 if true, 0 otherwise
 */
static inline int
is_power_of_2(uint32_t n)
{
	return n && !(n & (n - 1));
}

/**
 * Aligns input parameter to the next power of 2
 *
 * @param x
 * 	The integer value to align
 *
 * @return
 * 	Input parameter aligned to the next power of 2
 */
static inline uint32_t
align32pow2(uint32_t x)
{
	x--;
	x |= x >> 1;
	x |= x >> 2;
	x |= x >> 4;
	x |= x >> 8;
	x |= x >> 16;
	
	return x + 1;
}

static inline void
rte_pause(void)
{
	/* Do nothing */
}

#ifdef __cplusplus
}
#endif
#endif /* COMMON_H END*/
