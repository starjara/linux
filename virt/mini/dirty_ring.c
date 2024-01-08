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
