#ifndef __MINI_HOST_H
#define __MINI_HOST_H

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/rbtree.h>
#include <linux/hashtable.h>
#include <linux/interval_tree.h>
#include <linux/nospec.h>
#include <linux/rcuwait.h>
#include <linux/xarray.h>

#include <linux/mini.h>
#include <linux/mini_types.h>

#include <asm/mini_host.h>
//#include <linux/kvm_host.h>

#ifndef MINI_MAX_VCPU_IDS
#define MINI_MAX_VCPU_IDS MINI_MAX_VCPUS
#endif

#define MINI_MEMSLOT_INVALID	(1UL << 16)
#define MINI_MEMSLOT_GEN_UPDATE_IN_PROGRESS	BIT_ULL(63)

#ifndef MINI_ADDRESS_SPACE_NUM
#define MINI_ADDRESS_SPACE_NUM  1
#endif


#define mini_err(fmt, ...) \
    pr_err("mini [%i]: " fmt, task_pid_nr(current), ## __VA_ARGS__)
#define mini_info(fmt, ...) \
    pr_info("mini [%i]: " fmt, task_pid_nr(current), ## __VA_ARGS__)

struct mvm {
    int vmid;
};

#ifndef MINI_INTERNAL_MEM_SLOTS
#define MINI_INTERNAL_MEM_SLOTS 0
#endif

#define MINI_MEM_SLOTS_NUM SHRT_MAX
#define MINI_USER_MEM_SLOTS (MINI_MEM_SLOTS_NUM - MINI_INTERNAL_MEM_SLOTS)

#define MINI_REQUEST_MASK           GENMASK(7,0)
#define MINI_REQUEST_NO_WAKEUP      BIT(8)
#define MINI_REQUEST_WAIT           BIT(9)
#define MINI_REQUEST_NO_ACTION      BIT(10)

#define MINI_REQ_TLB_FLUSH		(0 | MINI_REQUEST_WAIT | MINI_REQUEST_NO_WAKEUP)
#define MINI_REQ_VM_DEAD			(1 | MINI_REQUEST_WAIT | MINI_REQUEST_NO_WAKEUP)
#define MINI_REQ_UNBLOCK			2
#define MINI_REQ_DIRTY_RING_SOFT_FULL	3
#define MINI_REQUEST_ARCH_BASE		8

#define MINI_ARCH_REQ_FLAGS(nr, flags) ({ \
	BUILD_BUG_ON((unsigned)(nr) >= (sizeof_field(struct mini_vcpu, requests) * 8) - MINI_REQUEST_ARCH_BASE); \
	(unsigned)(((nr) + MINI_REQUEST_ARCH_BASE) | (flags)); \
})
#define MINI_ARCH_REQ(nr)           MINI_ARCH_REQ_FLAGS(nr, 0)

bool mini_make_vcpus_request_mask(struct mini *mini, unsigned int req,
				 unsigned long *vcpu_bitmap);
bool mini_make_all_cpus_request(struct mini *mini, unsigned int req);
//bool mini_make_all_cpus_request_except(struct mini *mini, unsigned int req,
//				      struct mini_vcpu *except);
bool mini_make_cpus_request_mask(struct mini *mini, unsigned int req,
				unsigned long *vcpu_bitmap);

struct mini_memory_slot {
	struct hlist_node id_node[2];
	struct interval_tree_node hva_node[2];
	struct rb_node gfn_node[2];
	gfn_t base_gfn;
	unsigned long npages;
	unsigned long *dirty_bitmap;
	struct mini_arch_memory_slot arch;
	unsigned long userspace_addr;
	u32 flags;
	short id;
	u16 as_id;
};

struct mini_vcpu {
	struct mini *mini;
#ifdef CONFIG_PREEMPT_NOTIFIERS
	struct preempt_notifier preempt_notifier;
#endif
	int cpu;
	int vcpu_id; /* id given by userspace at creation */
	int vcpu_idx; /* index into mini->vcpu_array */
	int ____srcu_idx; /* Don't use this directly.  You've been warned. */
#ifdef CONFIG_PROVE_RCU
	int srcu_depth;
#endif
	int mode;
	u64 requests;
	unsigned long guest_debug;

	struct mutex mutex;
	struct mini_run *run;

#ifndef __MINI_HAVE_ARCH_WQP
	struct rcuwait wait;
#endif
	struct pid __rcu *pid;
	int sigset_active;
	sigset_t sigset;
	unsigned int halt_poll_ns;
	bool valid_wakeup;

/*
#ifdef CONFIG_HAS_IOMEM
	int mmio_needed;
	int mmio_read_completed;
	int mmio_is_write;
	int mmio_cur_fragment;
	int mmio_nr_fragments;
	struct mini_mmio_fragment mmio_fragments[MINI_MAX_MMIO_FRAGMENTS];
#endif

#ifdef CONFIG_MINI_ASYNC_PF
	struct {
		u32 queued;
		struct list_head queue;
		struct list_head done;
		spinlock_t lock;
	} async_pf;
#endif
*/

#ifdef CONFIG_HAVE_MINI_CPU_RELAX_INTERCEPT
	/*
	 * Cpu relax intercept or pause loop exit optimization
	 * in_spin_loop: set when a vcpu does a pause loop exit
	 *  or cpu relax intercepted.
	 * dy_eligible: indicates whether vcpu is eligible for directed yield.
	 */
	struct {
		bool in_spin_loop;
		bool dy_eligible;
	} spin_loop;
#endif
	bool preempted;
	bool ready;
	struct mini_vcpu_arch arch;
	struct mini_vcpu_stat stat;
	char stats_id[MINI_STATS_NAME_SIZE];
	//struct mini_dirty_ring dirty_ring;

	/*
	 * The most recently used memslot by this vCPU and the slots generation
	 * for which it is valid.
	 * No wraparound protection is needed since generations won't overflow in
	 * thousands of years, even assuming 1M memslot operations per second.
	 */
	struct mini_memory_slot *last_used_slot;
	u64 last_used_slot_gen;
};
static inline unsigned long mini_dirty_bitmap_bytes(struct mini_memory_slot *memslot)
{
	return ALIGN(memslot->npages, BITS_PER_LONG) / 8;
}

#define MINI_MEM_MAX_NR_PAGES ((1UL << 31) - 1)

struct mini_memslots {
	u64 generation;
	atomic_long_t last_used_slot;
	struct rb_root_cached hva_tree;
	struct rb_root gfn_tree;
	/*
	 * The mapping table from slot id to memslot.
	 *
	 * 7-bit bucket count matches the size of the old id to index array for
	 * 512 slots, while giving good performance with this slot count.
	 * Higher bucket counts bring only small performance improvements but
	 * always result in higher memory usage (even for lower memslot counts).
	 */
	DECLARE_HASHTABLE(id_hash, 7);
	int node_idx;
};

struct mini {
#ifdef MINI_HAVE_MMU_RWLOCK
	rwlock_t mmu_lock;
#else
	spinlock_t mmu_lock;
#endif /* MINI_HAVE_MMU_RWLOCK */

	struct mutex slots_lock;
	struct mutex slots_arch_lock;

	struct mm_struct *mm; /* userspace tied to this vm */

	unsigned long nr_memslot_pages;

	struct mini_vm_stat stat;
    struct mini_arch arch;
	refcount_t users_count;

	struct mini_memslots __memslots[MINI_ADDRESS_SPACE_NUM][2];
	struct mini_memslots __rcu *memslots[MINI_ADDRESS_SPACE_NUM];

	struct xarray vcpu_array;

	atomic_t nr_memslots_dirty_logging;

	struct mutex lock;

	atomic_t online_vcpus;
	int max_vcpus;
	int created_vcpus;

	spinlock_t mn_invalidate_lock;
	unsigned long mn_active_invalidate_count;
	struct rcuwait mn_memslots_update_rcuwait;

	struct srcu_struct srcu;

	u64 manual_dirty_log_protect;

    char stats_id[MINI_STATS_NAME_SIZE];
};

#ifndef __MINI_HAVE_ARCH_VM_ALLOC
static inline struct mini *mini_arch_alloc_vm(void)
{
    return kzalloc(sizeof(struct mini), GFP_KERNEL_ACCOUNT);
}
#endif

static inline struct mini_memslots *__mini_memslots(struct mini *mini, int as_id)
{
    mini_info("[mini] __mini_memslots\n");
	as_id = array_index_nospec(as_id, MINI_ADDRESS_SPACE_NUM);

	mini_info("[mini] __mini_memslots as_id : 0x%x\n", as_id);
	mini_info("[mini] __mini_memslots mini->memslots[as_id] : 0x%x\n", mini->memslots[as_id]);

	mini_info("[mini] __mini_memslots: 0x%x\n", 
            srcu_dereference_check(mini->memslots[as_id], &mini->srcu,
			lockdep_is_held(&mini->slots_lock) ||
			!refcount_read(&mini->users_count)));

	return srcu_dereference_check(mini->memslots[as_id], &mini->srcu,
			lockdep_is_held(&mini->slots_lock) ||
			!refcount_read(&mini->users_count));
}

static inline struct mini_memslots *mini_memslots(struct mini *mini)
{
	return __mini_memslots(mini, 0);
}

#define mini_for_each_vcpu(idx, vcpup, mini)		   \
	xa_for_each_range(&mini->vcpu_array, idx, vcpup, 0, \
			  (atomic_read(&mini->online_vcpus) - 1))

static inline
struct mini_memory_slot *id_to_memslot(struct mini_memslots *slots, int id)
{

    //mini_info("[mini] id_to_memslot\n");
	struct mini_memory_slot *slot;
	int idx = slots->node_idx;
    //mini_info("[mini] id_to_memslot %x, %x\n", idx, *slot);

	hash_for_each_possible(slots->id_hash, slot, id_node[idx], id) {
		if (slot->id == id)
			return slot;
	}

	return NULL;
} 

static inline struct mini_vcpu *mini_get_vcpu(struct mini *mini, int i)
{
	int num_vcpus = atomic_read(&mini->online_vcpus);
	i = array_index_nospec(i, num_vcpus);

	/* Pairs with smp_wmb() in mini_vm_ioctl_create_vcpu.  */
	smp_rmb();
	return xa_load(&mini->vcpu_array, i);
}

static inline struct mini_vcpu *mini_get_vcpu_by_id(struct mini *mini, int id)
{
	struct mini_vcpu *vcpu = NULL;
	unsigned long i;

	if (id < 0)
		return NULL;
	if (id < MINI_MAX_VCPUS)
		vcpu = mini_get_vcpu(mini, id);
	if (vcpu && vcpu->vcpu_id == id)
		return vcpu;
	mini_for_each_vcpu(i, vcpu, mini)
		if (vcpu->vcpu_id == id)
			return vcpu;
	return NULL;
}

struct mini_memslot_iter {
	struct mini_memslots *slots;
	struct rb_node *node;
	struct mini_memory_slot *slot;
};

static inline void mini_memslot_iter_next(struct mini_memslot_iter *iter)
{
	iter->node = rb_next(iter->node);
	if (!iter->node)
		return;

	iter->slot = container_of(iter->node, struct mini_memory_slot, gfn_node[iter->slots->node_idx]);
}

static inline void mini_memslot_iter_start(struct mini_memslot_iter *iter,
					  struct mini_memslots *slots,
					  gfn_t start)
{
	int idx = slots->node_idx;
	struct rb_node *tmp;
	struct mini_memory_slot *slot;

	iter->slots = slots;

	/*
	 * Find the so called "upper bound" of a key - the first node that has
	 * its key strictly greater than the searched one (the start gfn in our case).
	 */
	iter->node = NULL;
	for (tmp = slots->gfn_tree.rb_node; tmp; ) {
		slot = container_of(tmp, struct mini_memory_slot, gfn_node[idx]);
		if (start < slot->base_gfn) {
			iter->node = tmp;
			tmp = tmp->rb_left;
		} else {
			tmp = tmp->rb_right;
		}
	}

	/*
	 * Find the slot with the lowest gfn that can possibly intersect with
	 * the range, so we'll ideally have slot start <= range start
	 */
	if (iter->node) {
		/*
		 * A NULL previous node means that the very first slot
		 * already has a higher start gfn.
		 * In this case slot start > range start.
		 */
		tmp = rb_prev(iter->node);
		if (tmp)
			iter->node = tmp;
	} else {
		/* a NULL node below means no slots */
		iter->node = rb_last(&slots->gfn_tree);
	}

	if (iter->node) {
		iter->slot = container_of(iter->node, struct mini_memory_slot, gfn_node[idx]);

		/*
		 * It is possible in the slot start < range start case that the
		 * found slot ends before or at range start (slot end <= range start)
		 * and so it does not overlap the requested range.
		 *
		 * In such non-overlapping case the next slot (if it exists) will
		 * already have slot start > range start, otherwise the logic above
		 * would have found it instead of the current slot.
		 */
		if (iter->slot->base_gfn + iter->slot->npages <= start)
			mini_memslot_iter_next(iter);
	}
}

static inline bool mini_memslot_iter_is_valid(struct mini_memslot_iter *iter, gfn_t end)
{
	if (!iter->node)
		return false;

	/*
	 * If this slot starts beyond or at the end of the range so does
	 * every next one
	 */
	return iter->slot->base_gfn < end;
}
#define mini_for_each_memslot_in_gfn_range(iter, slots, start, end)	\
	for (mini_memslot_iter_start(iter, slots, start);		\
	     mini_memslot_iter_is_valid(iter, end);			\
	     mini_memslot_iter_next(iter))

enum mini_mr_change {
	MINI_MR_CREATE,
	MINI_MR_DELETE,
	MINI_MR_MOVE,
	MINI_MR_FLAGS_ONLY,
};

static inline void __mini_make_request(int req, struct mini_vcpu *vcpu)
{
	/*
	 * Ensure the rest of the request is published to mini_check_request's
	 * caller.  Paired with the smp_mb__after_atomic in mini_check_request.
	 */
	smp_wmb();
	set_bit(req & MINI_REQUEST_MASK, (void *)&vcpu->requests);
}

static inline bool mini_dirty_log_manual_protect_and_init_set(struct mini *mini)
{
	return !!(mini->manual_dirty_log_protect & MINI_DIRTY_LOG_INITIALLY_SET);
}

int mini_set_memory_region(struct mini *mini,
			  const struct mini_userspace_memory_region *mem);
int __mini_set_memory_region(struct mini *mini,
			    const struct mini_userspace_memory_region *mem);
int mini_init(unsigned size, unsigned align, struct module *module);
void mini_exit(void);

int mini_arch_init_vm(struct mini *mini, unsigned long type);

int mini_arch_enter(struct mini *mini);

#ifndef __MINI_HAVE_ARCH_FLUSH_REMOTE_TLB
static inline int mini_arch_flush_remote_tlb(struct mini *mini)
{
	return -ENOTSUPP;
}
#endif

void mini_arch_free_memslot(struct mini *mini, struct mini_memory_slot *slot);
void mini_arch_memslots_updated(struct mini *mini, u64 gen);
int mini_arch_prepare_memory_region(struct mini *mini,
				const struct mini_memory_slot *old,
				struct mini_memory_slot *new,
				enum mini_mr_change change);
void mini_arch_commit_memory_region(struct mini *mini,
				struct mini_memory_slot *old,
				const struct mini_memory_slot *new,
				enum mini_mr_change change);
/* flush all memory translations */
void mini_arch_flush_shadow_all(struct mini *mini);
/* flush memory translations pointing to 'slot' */
void mini_arch_flush_shadow_memslot(struct mini *mini,
				   struct mini_memory_slot *slot);
void mini_arch_guest_memory_reclaimed(struct mini *mini);

int mini_write_guest_page(struct mini *mini, gfn_t gfn, const void *data,
			 int offset, int len);
int mini_write_guest(struct mini *mini, gpa_t gpa, const void *data,
		    unsigned long len);

void mini_flush_remote_tlbs(struct mini *mini);

bool mini_vcpu_wake_up(struct mini_vcpu *vcpu);

static inline struct rcuwait *mini_arch_vcpu_get_wait(struct mini_vcpu *vcpu)
{
#ifdef __MINI_HAVE_ARCH_WQP
	return vcpu->arch.waitp;
#else
	return &vcpu->wait;
#endif
}

static inline bool __mini_vcpu_wake_up(struct mini_vcpu *vcpu)
{
	return !!rcuwait_wake_up(mini_arch_vcpu_get_wait(vcpu));
}

#ifdef MINI_ARCH_NR_OBJS_PER_MEMORY_CACHE
int mini_mmu_topup_memory_cache(struct mini_mmu_memory_cache *mc, int min);
int __mini_mmu_topup_memory_cache(struct mini_mmu_memory_cache *mc, int capacity, int min);
int mini_mmu_memory_cache_nr_free_objects(struct mini_mmu_memory_cache *mc);
void mini_mmu_free_memory_cache(struct mini_mmu_memory_cache *mc);
void *mini_mmu_memory_cache_alloc(struct mini_mmu_memory_cache *mc);
#endif

#ifdef CONFIG_MINI_GENERIC_DIRTYLOG_READ_PROTECT
void mini_arch_flush_remote_tlbs_memslot(struct mini *mini,
					const struct mini_memory_slot *memslot);
#else /* !CONFIG_MINI_GENERIC_DIRTYLOG_READ_PROTECT */
int mini_vm_ioctl_get_dirty_log(struct mini *mini, struct mini_dirty_log *log);
int mini_get_dirty_log(struct mini *mini, struct mini_dirty_log *log,
		      int *is_dirty, struct mini_memory_slot **memslot);
#endif

int mini_arch_vcpu_create(struct mini_vcpu *vcpu);
#endif
