#include <linux/mini_host.h>
#include <linux/mini.h>
#include <linux/vmalloc.h>
#include <linux/mini_dirty_ring.h>
//#include <trace/events/mini.h>
//
bool mini_use_dirty_bitmap(struct mini *mini)
{
	lockdep_assert_held(&mini->slots_lock);

	return !mini->dirty_ring_size || mini->dirty_ring_with_bitmap;
}

struct page *mini_dirty_ring_get_page(struct mini_dirty_ring *ring, u32 offset)
{
	return vmalloc_to_page((void *)ring->dirty_gfns + offset * PAGE_SIZE);
}

