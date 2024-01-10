#ifndef __MINI_TYPES_H__
#define __MINI_TYPES_H__

struct mini;
struct mini_memory_slot;
struct mini_memslots;
struct mini_vcpu;

#include <linux/types.h>

#include <asm/mini_types.h>


typedef unsigned long  gva_t;
typedef u64            gpa_t;
typedef u64            gfn_t;

#define INVALID_GPA	(~(gpa_t)0)

typedef unsigned long  hva_t;
typedef u64            hpa_t;
typedef u64            hfn_t;

typedef hfn_t mini_pfn_t;

#define MINI_STATS_NAME_SIZE	48

enum pfn_cache_usage {
	MINI_GUEST_USES_PFN = BIT(0),
	MINI_HOST_USES_PFN  = BIT(1),
	MINI_GUEST_AND_HOST_USE_PFN = MINI_GUEST_USES_PFN | MINI_HOST_USES_PFN,
};

#ifdef MINI_ARCH_NR_OBJS_PER_MEMORY_CACHE
/*
 * Memory caches are used to preallocate memory ahead of various MMU flows,
 * e.g. page fault handlers.  Gracefully handling allocation failures deep in
 * MMU flows is problematic, as is triggering reclaim, I/O, etc... while
 * holding MMU locks.  Note, these caches act more like prefetch buffers than
 * classical caches, i.e. objects are not returned to the cache on being freed.
 *
 * The @capacity field and @objects array are lazily initialized when the cache
 * is topped up (__mini_mmu_topup_memory_cache()).
 */
struct mini_mmu_memory_cache {
	gfp_t gfp_zero;
	gfp_t gfp_custom;
	struct kmem_cache *kmem_cache;
	int capacity;
	int nobjs;
	void **objects;
};
#endif

#define HALT_POLL_HIST_COUNT			32

struct mini_vm_stat_generic {
	u64 remote_tlb_flush;
	u64 remote_tlb_flush_requests;
};

struct mini_vcpu_stat_generic {
	u64 halt_successful_poll;
	u64 halt_attempted_poll;
	u64 halt_poll_invalid;
	u64 halt_wakeup;
	u64 halt_poll_success_ns;
	u64 halt_poll_fail_ns;
	u64 halt_wait_ns;
	u64 halt_poll_success_hist[HALT_POLL_HIST_COUNT];
	u64 halt_poll_fail_hist[HALT_POLL_HIST_COUNT];
	u64 halt_wait_hist[HALT_POLL_HIST_COUNT];
	u64 blocking;
};

#define MINI_STATS_NAME_SIZE	48
#endif
