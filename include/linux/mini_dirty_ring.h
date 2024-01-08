#ifndef MINI_DIRTY_RING_H
#define MINI_DIRTY_RING_H

#include <linux/mini.h>

#ifndef CONFIG_HAVE_MINI_DIRTY_RING
static inline bool mini_use_dirty_bitmap(struct mini *mini)
{
	return true;
}

#else /* CONFIG_HAVE_KVM_DIRTY_RING */
bool mini_use_dirty_bitmap(struct mini *mini);

#endif /* CONFIG_HAVE_KVM_DIRTY_RING */

#endif	/* MINI_DIRTY_RING_H */
