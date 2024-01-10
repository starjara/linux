#ifndef MINI_DIRTY_RING_H
#define MINI_DIRTY_RING_H

#include <linux/mini.h>

struct mini_dirty_ring {
	u32 dirty_index;
	u32 reset_index;
	u32 size;
	u32 soft_limit;
	struct mini_dirty_gfn *dirty_gfns;
	int index;
};

#ifndef CONFIG_HAVE_MINI_DIRTY_RING
static inline bool mini_use_dirty_bitmap(struct mini *mini)
{
	return true;
}

static inline struct page *mini_dirty_ring_get_page(struct mini_dirty_ring *ring,
						   u32 offset)
{
	return NULL;
}
#else /* CONFIG_HAVE_KVM_DIRTY_RING */

bool mini_use_dirty_bitmap(struct mini *mini);
struct page *mini_dirty_ring_get_page(struct mini_dirty_ring *ring, u32 offset);

#endif /* CONFIG_HAVE_KVM_DIRTY_RING */

#endif	/* MINI_DIRTY_RING_H */
