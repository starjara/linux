/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __VERSE_MM_H__
#define __VERSE_MM_H__ 1

/*
 * Architectures can choose whether to use an rwlock or spinlock
 * for the mmu_lock.  These macros, for use in common code
 * only, avoids using #ifdefs in places that must deal with
 * multiple architectures.
 */

#ifdef VERSE_HAVE_MMU_RWLOCK
#define VERSE_MMU_LOCK_INIT(verse)		rwlock_init(&(verse)->mmu_lock)
#define VERSE_MMU_LOCK(verse)		write_lock(&(verse)->mmu_lock)
#define VERSE_MMU_UNLOCK(verse)		write_unlock(&(verse)->mmu_lock)
#else
#define VERSE_MMU_LOCK_INIT(verse)		spin_lock_init(&(verse)->mmu_lock)
#define VERSE_MMU_LOCK(verse)		spin_lock(&(verse)->mmu_lock)
#define VERSE_MMU_UNLOCK(verse)		spin_unlock(&(verse)->mmu_lock)
#endif // VERSE_HAVE_MMU_RWLOCK

#endif // __VERSE_MM_H__
