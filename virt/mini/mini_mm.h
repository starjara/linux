/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __MINI_MM_H__
#define __MINI_MM_H__ 1

/*
 * Architectures can choose whether to use an rwlock or spinlock
 * for the mmu_lock.  These macros, for use in common code
 * only, avoids using #ifdefs in places that must deal with
 * multiple architectures.
 */

#ifdef MINI_HAVE_MMU_RWLOCK
#define MINI_MMU_LOCK_INIT(mini)		rwlock_init(&(mini)->mmu_lock)
#define MINI_MMU_LOCK(mini)		write_lock(&(mini)->mmu_lock)
#define MINI_MMU_UNLOCK(mini)		write_unlock(&(mini)->mmu_lock)
#else
#define MINI_MMU_LOCK_INIT(mini)		spin_lock_init(&(mini)->mmu_lock)
#define MINI_MMU_LOCK(mini)		spin_lock(&(mini)->mmu_lock)
#define MINI_MMU_UNLOCK(mini)		spin_unlock(&(mini)->mmu_lock)
#endif /* MINI_HAVE_MMU_RWLOCK */

mini_pfn_t hva_to_pfn(unsigned long addr, bool atomic, bool interruptible,
		     bool *async, bool write_fault, bool *writable);

#ifdef CONFIG_HAVE_MINI_PFNCACHE
void gfn_to_pfn_cache_invalidate_start(struct mini *mini,
				       unsigned long start,
				       unsigned long end,
				       bool may_block);
#else
static inline void gfn_to_pfn_cache_invalidate_start(struct mini *mini,
						     unsigned long start,
						     unsigned long end,
						     bool may_block)
{
}
#endif /* HAVE_MINI_PFNCACHE */

#endif /* __MINI_MM_H__ */
