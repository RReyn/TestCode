#ifndef __SPIN_LOCK_H__
#define __SPIN_LOCK_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	volatile int locked; /* lock status 0 = unlocked, 1 = locked */
} rte_spinlock_t;

/*
 * Initialize the spinlock to an unlocked state.
 *
 * @param sl
 * 	A pointer to the spinlock
 */
static inline void
rte_spinlock_init(rte_spinlock_t *sl)
{
	sl->locked = 0;
}

/*
 * Take the spinlock
 *
 * @param sl
 * 	A pointer to the spinlock
 */
static inline void
rte_spinlock_lock(rte_spinlock_t *sl)
{
	while (__sync_lock_test_and_set(&sl->locked, 1)) {

	}
}

/*
 * Relase the spinlock
 *
 * @param sl
 * 	A pointer to the spinlock
 */
static inline void
rte_spinlock_unlock(rte_spinlock_t *sl)
{
	__sync_lock_release(&sl->locked);
}

#ifdef __cplusplus
}
#endif

#endif /* SPIN_LOCK END*/
