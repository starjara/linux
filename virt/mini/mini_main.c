#include <linux/mini_host.h>
#include <linux/mini.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/vmalloc.h>
#include <linux/debugfs.h>
#include <linux/file.h>
#include <linux/cpumask.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/types.h>
//#include <linux/mini_types.h>
#include <linux/fs.h>
#include <linux/anon_inodes.h>
#include <linux/mman.h>

#include <asm/processor.h>
#include <asm/ioctl.h>
#include <linux/uaccess.h>

#include "mini_mm.h"

#include <linux/mini_dirty_ring.h>
#define ITOA_MAX_LEN 12

#define DEVICE_NAME "mini"

MODULE_AUTHOR("JARA");
MODULE_LICENSE("GPL");

struct dentry *mini_debugfs_dir;
static int major;
static struct class *cls;
static struct file_operations mini_chardev_ops;

static DEFINE_PER_CPU(struct mini_vcpu *, mini_running_vcpu);
static DEFINE_PER_CPU(cpumask_var_t, cpu_kick_mask);

static struct kmem_cache *mini_vcpu_cache;

static long mini_vcpu_ioctl(struct file *file, unsigned int ioctl,
			   unsigned long arg);
#ifdef CONFIG_MINI_COMPAT
static long mini_vcpu_compat_ioctl(struct file *file, unsigned int ioctl,
				  unsigned long arg);
#define MINI_COMPAT(c)	.compat_ioctl	= (c)
#else
/*
 * For architectures that don't implement a compat infrastructure,
 * adopt a double line of defense:
 * - Prevent a compat task from opening /dev/kvm
 * - If the open has been done by a 64bit task, and the MINI fd
 *   passed to a compat task, let the ioctls fail.
 */
static long mini_no_compat_ioctl(struct file *file, unsigned int ioctl,
				unsigned long arg) { return -EINVAL; }

static int mini_no_compat_open(struct inode *inode, struct file *file)
{
	return is_compat_task() ? -ENODEV : 0;
}
#define MINI_COMPAT(c)	.compat_ioctl	= mini_no_compat_ioctl,	\
			.open		= mini_no_compat_open
#endif

__weak void mini_arch_guest_memory_reclaimed(struct mini *mini)
{
}

static void ack_kick(void *_completed)
{
}

bool mini_is_zone_device_page(struct page *page)
{
	/*
	 * The metadata used by is_zone_device_page() to determine whether or
	 * not a page is ZONE_DEVICE is guaranteed to be valid if and only if
	 * the device has been pinned, e.g. by get_user_pages().  WARN if the
	 * page_count() is zero to help detect bad usage of this helper.
	 */
	if (WARN_ON_ONCE(!page_count(page)))
		return false;

	return is_zone_device_page(page);
}

struct page *mini_pfn_to_refcounted_page(mini_pfn_t pfn)
{
	struct page *page;

	if (!pfn_valid(pfn))
		return NULL;

	page = pfn_to_page(pfn);
	if (!PageReserved(page))
		return page;

	/* The ZERO_PAGE(s) is marked PG_reserved, but is refcounted. */
	if (is_zero_pfn(pfn))
		return page;

	/*
	 * ZONE_DEVICE pages currently set PG_reserved, but from a refcounting
	 * perspective they are "normal" pages, albeit with slightly different
	 * usage rules.
	 */
	if (mini_is_zone_device_page(page))
		return page;

	return NULL;
}
static inline bool mini_kick_many_cpus(struct cpumask *cpus, bool wait)
{
	if (cpumask_empty(cpus))
		return false;

	smp_call_function_many(cpus, ack_kick, NULL, wait);
	return true;
}

static void mini_make_vcpu_request(struct mini_vcpu *vcpu, unsigned int req,
				  struct cpumask *tmp, int current_cpu)
{
	int cpu;

	if (likely(!(req & MINI_REQUEST_NO_ACTION)))
		__mini_make_request(req, vcpu);

	if (!(req & MINI_REQUEST_NO_WAKEUP) && mini_vcpu_wake_up(vcpu))
		return;

	/*
	 * Note, the vCPU could get migrated to a different pCPU at any point
	 * after mini_request_needs_ipi(), which could result in sending an IPI
	 * to the previous pCPU.  But, that's OK because the purpose of the IPI
	 * is to ensure the vCPU returns to OUTSIDE_GUEST_MODE, which is
	 * satisfied if the vCPU migrates. Entering READING_SHADOW_PAGE_TABLES
	 * after this point is also OK, as the requirement is only that MINI wait
	 * for vCPUs that were reading SPTEs _before_ any changes were
	 * finalized. See mini_vcpu_kick() for more details on handling requests.
	 */
    /*
	if (mini_request_needs_ipi(vcpu, req)) {
		cpu = READ_ONCE(vcpu->cpu);
		if (cpu != -1 && cpu != current_cpu)
			__cpumask_set_cpu(cpu, tmp);
	}
    */
}

bool mini_make_vcpus_request_mask(struct mini *mini, unsigned int req,
				 unsigned long *vcpu_bitmap)
{
	struct mini_vcpu *vcpu;
	struct cpumask *cpus;
	int i, me;
	bool called;

	me = get_cpu();

	cpus = this_cpu_cpumask_var_ptr(cpu_kick_mask);
	cpumask_clear(cpus);

	for_each_set_bit(i, vcpu_bitmap, MINI_MAX_VCPUS) {
		vcpu = mini_get_vcpu(mini, i);
		if (!vcpu)
			continue;
		mini_make_vcpu_request(vcpu, req, cpus, me);
	}

	called = mini_kick_many_cpus(cpus, !!(req & MINI_REQUEST_WAIT));
	put_cpu();

	return called;
}

bool mini_make_all_cpus_request_except(struct mini *mini, unsigned int req,
				      struct mini_vcpu *except)
{
	struct mini_vcpu *vcpu;
	struct cpumask *cpus;
	unsigned long i;
	bool called;
	int me;

	me = get_cpu();

	cpus = this_cpu_cpumask_var_ptr(cpu_kick_mask);
	cpumask_clear(cpus);

	mini_for_each_vcpu(i, vcpu, mini) {
		if (vcpu == except)
			continue;
		mini_make_vcpu_request(vcpu, req, cpus, me);
	}

	called = mini_kick_many_cpus(cpus, !!(req & MINI_REQUEST_WAIT));
	put_cpu();

	return called;
}

bool mini_make_all_cpus_request(struct mini *mini, unsigned int req)
{
	return mini_make_all_cpus_request_except(mini, req, NULL);
}
EXPORT_SYMBOL_GPL(mini_make_all_cpus_request);

#ifndef CONFIG_HAVE_MINI_ARCH_TLB_FLUSH_ALL
void mini_flush_remote_tlbs(struct mini *mini)
{
	++mini->stat.generic.remote_tlb_flush_requests;

	/*
	 * We want to publish modifications to the page tables before reading
	 * mode. Pairs with a memory barrier in arch-specific code.
	 * - x86: smp_mb__after_srcu_read_unlock in vcpu_enter_guest
	 * and smp_mb in walk_shadow_page_lockless_begin/end.
	 * - powerpc: smp_mb in minippc_prepare_to_enter.
	 *
	 * There is already an smp_mb__after_atomic() before
	 * mini_make_all_cpus_request() reads vcpu->mode. We reuse that
	 * barrier here.
	 */
	if (!mini_arch_flush_remote_tlb(mini)
	    || mini_make_all_cpus_request(mini, MINI_REQ_TLB_FLUSH))
		++mini->stat.generic.remote_tlb_flush;
}
EXPORT_SYMBOL_GPL(mini_flush_remote_tlbs);
#endif

#ifdef MINI_ARCH_NR_OBJS_PER_MEMORY_CACHE
static inline void *mmu_memory_cache_alloc_obj(struct mini_mmu_memory_cache *mc,
					       gfp_t gfp_flags)
{
	gfp_flags |= mc->gfp_zero;

	if (mc->kmem_cache)
		return kmem_cache_alloc(mc->kmem_cache, gfp_flags);
	else
		return (void *)__get_free_page(gfp_flags);
}

int __mini_mmu_topup_memory_cache(struct mini_mmu_memory_cache *mc, int capacity, int min)
{
	gfp_t gfp = mc->gfp_custom ? mc->gfp_custom : GFP_KERNEL_ACCOUNT;
	void *obj;

	if (mc->nobjs >= min)
		return 0;

	if (unlikely(!mc->objects)) {
		if (WARN_ON_ONCE(!capacity))
			return -EIO;

		mc->objects = kvmalloc_array(sizeof(void *), capacity, gfp);
		if (!mc->objects)
			return -ENOMEM;

		mc->capacity = capacity;
	}

	/* It is illegal to request a different capacity across topups. */
	if (WARN_ON_ONCE(mc->capacity != capacity))
		return -EIO;

	while (mc->nobjs < mc->capacity) {
		obj = mmu_memory_cache_alloc_obj(mc, gfp);
		if (!obj)
			return mc->nobjs >= min ? 0 : -ENOMEM;
		mc->objects[mc->nobjs++] = obj;
	}
	return 0;
}

int mini_mmu_topup_memory_cache(struct mini_mmu_memory_cache *mc, int min)
{
	return __mini_mmu_topup_memory_cache(mc, MINI_ARCH_NR_OBJS_PER_MEMORY_CACHE, min);
}

int mini_mmu_memory_cache_nr_free_objects(struct mini_mmu_memory_cache *mc)
{
	return mc->nobjs;
}

void mini_mmu_free_memory_cache(struct mini_mmu_memory_cache *mc)
{
	while (mc->nobjs) {
		if (mc->kmem_cache)
			kmem_cache_free(mc->kmem_cache, mc->objects[--mc->nobjs]);
		else
			free_page((unsigned long)mc->objects[--mc->nobjs]);
	}

	kvfree(mc->objects);

	mc->objects = NULL;
	mc->capacity = 0;
}

void *mini_mmu_memory_cache_alloc(struct mini_mmu_memory_cache *mc)
{
	void *p;

	if (WARN_ON(!mc->nobjs))
		p = mmu_memory_cache_alloc_obj(mc, GFP_ATOMIC | __GFP_ACCOUNT);
	else
		p = mc->objects[--mc->nobjs];
	BUG_ON(!p);
	return p;
}
#endif

static int check_memory_region_flags(const struct mini_userspace_memory_region *mem)
{
	u32 valid_flags = MINI_MEM_LOG_DIRTY_PAGES;

#ifdef __MINI_HAVE_READONLY_MEM
	valid_flags |= MINI_MEM_READONLY;
#endif

	if (mem->flags & ~valid_flags)
		return -EINVAL;

	return 0;
}

__weak void mini_arch_mmu_notifier_invalidate_range(struct mini *mini,
						   unsigned long start, unsigned long end)
{
}

static struct mini_memslots *mini_get_inactive_memslots(struct mini *mini, int as_id)
{
	struct mini_memslots *active = __mini_memslots(mini, as_id);
	int node_idx_inactive = active->node_idx ^ 1;

	return &mini->__memslots[as_id][node_idx_inactive];
}

static void mini_swap_active_memslots(struct mini *mini, int as_id)
{
	struct mini_memslots *slots = mini_get_inactive_memslots(mini, as_id);
    mini_info("[mini] mini_swap_active_memslots\n");

	/* Grab the generation from the activate memslots. */
	u64 gen = __mini_memslots(mini, as_id)->generation;

	WARN_ON(gen & MINI_MEMSLOT_GEN_UPDATE_IN_PROGRESS);
	slots->generation = gen | MINI_MEMSLOT_GEN_UPDATE_IN_PROGRESS;

	/*
	 * Do not store the new memslots while there are invalidations in
	 * progress, otherwise the locking in invalidate_range_start and
	 * invalidate_range_end will be unbalanced.
	 */
	spin_lock(&mini->mn_invalidate_lock);
	prepare_to_rcuwait(&mini->mn_memslots_update_rcuwait);
	while (mini->mn_active_invalidate_count) {
		set_current_state(TASK_UNINTERRUPTIBLE);
		spin_unlock(&mini->mn_invalidate_lock);
		schedule();
		spin_lock(&mini->mn_invalidate_lock);
	}
	finish_rcuwait(&mini->mn_memslots_update_rcuwait);
	rcu_assign_pointer(mini->memslots[as_id], slots);
	spin_unlock(&mini->mn_invalidate_lock);

	/*
	 * Acquired in mini_set_memslot. Must be released before synchronize
	 * SRCU below in order to avoid deadlock with another thread
	 * acquiring the slots_arch_lock in an srcu critical section.
	 */
	mutex_unlock(&mini->slots_arch_lock);

    mini_info("[mini] synchronize_srcu_expedited()\n");
	synchronize_srcu_expedited(&mini->srcu);

	/*
	 * Increment the new memslot generation a second time, dropping the
	 * update in-progress flag and incrementing the generation based on
	 * the number of address spaces.  This provides a unique and easily
	 * identifiable generation number while the memslots are in flux.
	 */
	gen = slots->generation & ~MINI_MEMSLOT_GEN_UPDATE_IN_PROGRESS;

	/*
	 * Generations must be unique even across address spaces.  We do not need
	 * a global counter for that, instead the generation space is evenly split
	 * across address spaces.  For example, with two address spaces, address
	 * space 0 will use generations 0, 2, 4, ... while address space 1 will
	 * use generations 1, 3, 5, ...
	 */
	gen += MINI_ADDRESS_SPACE_NUM;

	mini_arch_memslots_updated(mini, gen);

	slots->generation = gen;
}

static void mini_copy_memslot(struct mini_memory_slot *dest,
			     const struct mini_memory_slot *src)
{
	dest->base_gfn = src->base_gfn;
	dest->npages = src->npages;
	dest->dirty_bitmap = src->dirty_bitmap;
	dest->arch = src->arch;
	dest->userspace_addr = src->userspace_addr;
	dest->flags = src->flags;
	dest->id = src->id;
	dest->as_id = src->as_id;
}



static struct mini *mini_create_vm(unsigned long type, const char *fdname)
{
    struct mini *mini = mini_arch_alloc_vm();
    struct mini_memslots *slots;
    int r = -ENOMEM;
    int i, j;

    mini_info("[mini] mini : 0x%x\n", *mini);

    if(!mini)
        return ERR_PTR(-ENOMEM);

    mini_info("[mini] mini_create_vm\n");

    __module_get(mini_chardev_ops.owner);

	MINI_MMU_LOCK_INIT(mini);
	mmgrab(current->mm);
	mini->mm = current->mm;
	//mini_eventfd_init(mini);
	//mutex_init(&mini->lock);
	//mutex_init(&mini->irq_lock);
	mutex_init(&mini->slots_lock);
	mutex_init(&mini->slots_arch_lock);
	spin_lock_init(&mini->mn_invalidate_lock);
	rcuwait_init(&mini->mn_memslots_update_rcuwait);
	xa_init(&mini->vcpu_array);

	mini->max_vcpus = MINI_MAX_VCPUS;

	snprintf(mini->stats_id, sizeof(mini->stats_id), "mini-%d",
		 task_pid_nr(current));

	if (init_srcu_struct(&mini->srcu))
        return NULL;
		//goto out_err_no_srcu;
	//if (init_srcu_struct(&mini->irq_srcu))
        //return NULL;
		//goto out_err_no_irq_srcu;

	for (i = 0; i < MINI_ADDRESS_SPACE_NUM; i++) {
		for (j = 0; j < 2; j++) {
            slots = &mini->__memslots[i][j];

			atomic_long_set(&slots->last_used_slot, (unsigned long)NULL);
            slots->hva_tree = RB_ROOT_CACHED;
            slots->gfn_tree = RB_ROOT;
            hash_init(slots->id_hash);
            slots->node_idx = j;

            slots->generation = i;
        }
		rcu_assign_pointer(mini->memslots[i], &mini->__memslots[i][0]);
    }

    r = mini_arch_init_vm(mini, type);

    return mini;
}






/*
 * Allocation size is twice as large as the actual dirty bitmap size.
 * See mini_vm_ioctl_get_dirty_log() why this is needed.
 */
static int mini_alloc_dirty_bitmap(struct mini_memory_slot *memslot)
{
	unsigned long dirty_bytes = mini_dirty_bitmap_bytes(memslot);

	memslot->dirty_bitmap = __vcalloc(2, dirty_bytes, GFP_KERNEL_ACCOUNT);
	if (!memslot->dirty_bitmap)
		return -ENOMEM;

	return 0;
}

static void mini_destroy_dirty_bitmap(struct mini_memory_slot *memslot)
{
	if (!memslot->dirty_bitmap)
		return;

	kvfree(memslot->dirty_bitmap);
	memslot->dirty_bitmap = NULL;
}

/* This does not remove the slot from struct mini_memslots data structures */
static void mini_free_memslot(struct mini *mini, struct mini_memory_slot *slot)
{
	mini_destroy_dirty_bitmap(slot);

	mini_arch_free_memslot(mini, slot);

	kfree(slot);
}

static void mini_free_memslots(struct mini *mini, struct mini_memslots *slots)
{
	struct hlist_node *idnode;
	struct mini_memory_slot *memslot;
	int bkt;

	/*
	 * The same memslot objects live in both active and inactive sets,
	 * arbitrarily free using index '1' so the second invocation of this
	 * function isn't operating over a structure with dangling pointers
	 * (even though this function isn't actually touching them).
	 */
	if (!slots->node_idx)
		return;

	hash_for_each_safe(slots->id_hash, bkt, idnode, memslot, id_node[1])
		mini_free_memslot(mini, memslot);
}

static void mini_commit_memory_region(struct mini *mini,
				     struct mini_memory_slot *old,
				     const struct mini_memory_slot *new,
				     enum mini_mr_change change)
{
	int old_flags = old ? old->flags : 0;
	int new_flags = new ? new->flags : 0;
    mini_info("[mini] mini_commit_memory_region\n");
	/*
	 * Update the total number of memslot pages before calling the arch
	 * hook so that architectures can consume the result directly.
	 */
	if (change == MINI_MR_DELETE)
		mini->nr_memslot_pages -= old->npages;
	else if (change == MINI_MR_CREATE)
		mini->nr_memslot_pages += new->npages;

	if ((old_flags ^ new_flags) & MINI_MEM_LOG_DIRTY_PAGES) {
		int change = (new_flags & MINI_MEM_LOG_DIRTY_PAGES) ? 1 : -1;
		atomic_set(&mini->nr_memslots_dirty_logging,
			   atomic_read(&mini->nr_memslots_dirty_logging) + change);
	}

	mini_arch_commit_memory_region(mini, old, new, change);

	switch (change) {
	case MINI_MR_CREATE:
		/* Nothing more to do. */
		break;
	case MINI_MR_DELETE:
		/* Free the old memslot and all its metadata. */
		mini_free_memslot(mini, old);
		break;
	case MINI_MR_MOVE:
	case MINI_MR_FLAGS_ONLY:
		/*
		 * Free the dirty bitmap as needed; the below check encompasses
		 * both the flags and whether a ring buffer is being used)
		 */
		if (old->dirty_bitmap && !new->dirty_bitmap)
			mini_destroy_dirty_bitmap(old);

		/*
		 * The final quirk.  Free the detached, old slot, but only its
		 * memory, not any metadata.  Metadata, including arch specific
		 * data, may be reused by @new.
		 */
		kfree(old);
		break;
	default:
		BUG();
	}
}

 int mini_prepare_memory_region(struct mini *mini,
				     const struct mini_memory_slot *old,
				     struct mini_memory_slot *new,
				     enum mini_mr_change change)
{
	int r;

    mini_info("[mini] mini_prepare_memory_region\n");

	/*
	 * If dirty logging is disabled, nullify the bitmap; the old bitmap
	 * will be freed on "commit".  If logging is enabled in both old and
	 * new, reuse the existing bitmap.  If logging is enabled only in the
	 * new and MINI isn't using a ring buffer, allocate and initialize a
	 * new bitmap.
	 */
	if (change != MINI_MR_DELETE) {
		if (!(new->flags & MINI_MEM_LOG_DIRTY_PAGES))
			new->dirty_bitmap = NULL;
		else if (old && old->dirty_bitmap)
			new->dirty_bitmap = old->dirty_bitmap;
		else if (mini_use_dirty_bitmap(mini)) {
			r = mini_alloc_dirty_bitmap(new);
			if (r)
				return r;

			if (mini_dirty_log_manual_protect_and_init_set(mini))
				bitmap_set(new->dirty_bitmap, 0, new->npages);
		}
	}

	r = mini_arch_prepare_memory_region(mini, old, new, change);

	/* Free the bitmap on failure if it was allocated above. */
	if (r && new && new->dirty_bitmap && (!old || !old->dirty_bitmap))
		mini_destroy_dirty_bitmap(new);

	return r;
}

/*
 * Helper to get the address space ID when one of memslot pointers may be NULL.
 * This also serves as a sanity that at least one of the pointers is non-NULL,
 * and that their address space IDs don't diverge.
 */
static int mini_memslots_get_as_id(struct mini_memory_slot *a,
				  struct mini_memory_slot *b)
{
	if (WARN_ON_ONCE(!a && !b))
		return 0;

	if (!a)
		return b->as_id;
	if (!b)
		return a->as_id;

	WARN_ON_ONCE(a->as_id != b->as_id);
	return a->as_id;
}

static void mini_insert_gfn_node(struct mini_memslots *slots,
				struct mini_memory_slot *slot)
{
	struct rb_root *gfn_tree = &slots->gfn_tree;
	struct rb_node **node, *parent;
	int idx = slots->node_idx;

	parent = NULL;
	for (node = &gfn_tree->rb_node; *node; ) {
		struct mini_memory_slot *tmp;

		tmp = container_of(*node, struct mini_memory_slot, gfn_node[idx]);
		parent = *node;
		if (slot->base_gfn < tmp->base_gfn)
			node = &(*node)->rb_left;
		else if (slot->base_gfn > tmp->base_gfn)
			node = &(*node)->rb_right;
		else
			BUG();
	}

	rb_link_node(&slot->gfn_node[idx], parent, node);
	rb_insert_color(&slot->gfn_node[idx], gfn_tree);
}

static void mini_erase_gfn_node(struct mini_memslots *slots,
			       struct mini_memory_slot *slot)
{
	rb_erase(&slot->gfn_node[slots->node_idx], &slots->gfn_tree);
}

static void mini_replace_gfn_node(struct mini_memslots *slots,
				 struct mini_memory_slot *old,
				 struct mini_memory_slot *new)
{
	int idx = slots->node_idx;

	WARN_ON_ONCE(old->base_gfn != new->base_gfn);

	rb_replace_node(&old->gfn_node[idx], &new->gfn_node[idx],
			&slots->gfn_tree);
}

/*
 * Replace @old with @new in the inactive memslots.
 *
 * With NULL @old this simply adds @new.
 * With NULL @new this simply removes @old.
 *
 * If @new is non-NULL its hva_node[slots_idx] range has to be set
 * appropriately.
 */
static void mini_replace_memslot(struct mini *mini,
				struct mini_memory_slot *old,
				struct mini_memory_slot *new)
{
	int as_id = mini_memslots_get_as_id(old, new);
	struct mini_memslots *slots = mini_get_inactive_memslots(mini, as_id);
	int idx = slots->node_idx;

    mini_info("[mini] mini_replace_memslot\n");
	if (old) {
		hash_del(&old->id_node[idx]);
		interval_tree_remove(&old->hva_node[idx], &slots->hva_tree);

		if ((long)old == atomic_long_read(&slots->last_used_slot))
			atomic_long_set(&slots->last_used_slot, (long)new);

		if (!new) {
			mini_erase_gfn_node(slots, old);
			return;
		}
	}

	/*
	 * Initialize @new's hva range.  Do this even when replacing an @old
	 * slot, mini_copy_memslot() deliberately does not touch node data.
	 */
	new->hva_node[idx].start = new->userspace_addr;
	new->hva_node[idx].last = new->userspace_addr +
				  (new->npages << PAGE_SHIFT) - 1;

	/*
	 * (Re)Add the new memslot.  There is no O(1) interval_tree_replace(),
	 * hva_node needs to be swapped with remove+insert even though hva can't
	 * change when replacing an existing slot.
	 */
	hash_add(slots->id_hash, &new->id_node[idx], new->id);
	interval_tree_insert(&new->hva_node[idx], &slots->hva_tree);

	/*
	 * If the memslot gfn is unchanged, rb_replace_node() can be used to
	 * switch the node in the gfn tree instead of removing the old and
	 * inserting the new as two separate operations. Replacement is a
	 * single O(1) operation versus two O(log(n)) operations for
	 * remove+insert.
	 */
	if (old && old->base_gfn == new->base_gfn) {
		mini_replace_gfn_node(slots, old, new);
	} else {
		if (old)
			mini_erase_gfn_node(slots, old);
		mini_insert_gfn_node(slots, new);
	}
}

static void mini_invalidate_memslot(struct mini *mini,
				   struct mini_memory_slot *old,
				   struct mini_memory_slot *invalid_slot)
{
	/*
	 * Mark the current slot INVALID.  As with all memslot modifications,
	 * this must be done on an unreachable slot to avoid modifying the
	 * current slot in the active tree.
	 */
	mini_copy_memslot(invalid_slot, old);
	invalid_slot->flags |= MINI_MEMSLOT_INVALID;
	mini_replace_memslot(mini, old, invalid_slot);

	/*
	 * Activate the slot that is now marked INVALID, but don't propagate
	 * the slot to the now inactive slots. The slot is either going to be
	 * deleted or recreated as a new slot.
	 */
	mini_swap_active_memslots(mini, old->as_id);

	/*
	 * From this point no new shadow pages pointing to a deleted, or moved,
	 * memslot will be created.  Validation of sp->gfn happens in:
	 *	- gfn_to_hva (mini_read_guest, gfn_to_pfn)
	 *	- mini_is_visible_gfn (mmu_check_root)
	 */
	mini_arch_flush_shadow_memslot(mini, old);
	mini_arch_guest_memory_reclaimed(mini);

	/* Was released by mini_swap_active_memslots(), reacquire. */
	mutex_lock(&mini->slots_arch_lock);

	/*
	 * Copy the arch-specific field of the newly-installed slot back to the
	 * old slot as the arch data could have changed between releasing
	 * slots_arch_lock in mini_swap_active_memslots() and re-acquiring the lock
	 * above.  Writers are required to retrieve memslots *after* acquiring
	 * slots_arch_lock, thus the active slot's data is guaranteed to be fresh.
	 */
	old->arch = invalid_slot->arch;
}

/*
 * Activate @new, which must be installed in the inactive slots by the caller,
 * by swapping the active slots and then propagating @new to @old once @old is
 * unreachable and can be safely modified.
 *
 * With NULL @old this simply adds @new to @active (while swapping the sets).
 * With NULL @new this simply removes @old from @active and frees it
 * (while also swapping the sets).
 */
static void mini_activate_memslot(struct mini *mini,
				 struct mini_memory_slot *old,
				 struct mini_memory_slot *new)
{
	int as_id = mini_memslots_get_as_id(old, new);

    mini_info("[mini] mini_activate_memslot\n");

	mini_swap_active_memslots(mini, as_id);

	/* Propagate the new memslot to the now inactive memslots. */
	mini_replace_memslot(mini, old, new);
}


static void mini_update_flags_memslot(struct mini *mini,
				     struct mini_memory_slot *old,
				     struct mini_memory_slot *new)
{
	/*
	 * Similar to the MOVE case, but the slot doesn't need to be zapped as
	 * an intermediate step. Instead, the old memslot is simply replaced
	 * with a new, updated copy in both memslot sets.
	 */
    mini_info("[mini] mini_update_flags_memslot\n");
	mini_replace_memslot(mini, old, new);
	mini_activate_memslot(mini, old, new);
}

static void mini_create_memslot(struct mini *mini,
			       struct mini_memory_slot *new)
{
	/* Add the new memslot to the inactive set and activate. */
    mini_info("[mini] mini_create_memslot\n");
	mini_replace_memslot(mini, NULL, new);
	mini_activate_memslot(mini, NULL, new);
}

static void mini_delete_memslot(struct mini *mini,
			       struct mini_memory_slot *old,
			       struct mini_memory_slot *invalid_slot)
{
	/*
	 * Remove the old memslot (in the inactive memslots) by passing NULL as
	 * the "new" slot, and for the invalid version in the active slots.
	 */
    mini_info("[mini] mini_delete_memslot\n");
	mini_replace_memslot(mini, old, NULL);
	mini_activate_memslot(mini, invalid_slot, NULL);
}

static void mini_move_memslot(struct mini *mini,
			     struct mini_memory_slot *old,
			     struct mini_memory_slot *new,
			     struct mini_memory_slot *invalid_slot)
{
	/*
	 * Replace the old memslot in the inactive slots, and then swap slots
	 * and replace the current INVALID with the new as well.
	 */
    mini_info("[mini] mini_move_memslot\n");
	mini_replace_memslot(mini, old, new);
	mini_activate_memslot(mini, invalid_slot, new);
}

static int mini_set_memslot(struct mini *mini,
			   struct mini_memory_slot *old,
			   struct mini_memory_slot *new,
			   enum mini_mr_change change)
{
	struct mini_memory_slot *invalid_slot;
	int r;

    mini_info("[mini] mini_set_memslot\n");
	/*
	 * Released in mini_swap_active_memslots().
	 *
	 * Must be held from before the current memslots are copied until after
	 * the new memslots are installed with rcu_assign_pointer, then
	 * released before the synchronize srcu in mini_swap_active_memslots().
	 *
	 * When modifying memslots outside of the slots_lock, must be held
	 * before reading the pointer to the current memslots until after all
	 * changes to those memslots are complete.
	 *
	 * These rules ensure that installing new memslots does not lose
	 * changes made to the previous memslots.
	 */
	mutex_lock(&mini->slots_arch_lock);

	/*
	 * Invalidate the old slot if it's being deleted or moved.  This is
	 * done prior to actually deleting/moving the memslot to allow vCPUs to
	 * continue running by ensuring there are no mappings or shadow pages
	 * for the memslot when it is deleted/moved.  Without pre-invalidation
	 * (and without a lock), a window would exist between effecting the
	 * delete/move and committing the changes in arch code where MINI or a
	 * guest could access a non-existent memslot.
	 *
	 * Modifications are done on a temporary, unreachable slot.  The old
	 * slot needs to be preserved in case a later step fails and the
	 * invalidation needs to be reverted.
	 */
	if (change == MINI_MR_DELETE || change == MINI_MR_MOVE) {
		invalid_slot = kzalloc(sizeof(*invalid_slot), GFP_KERNEL_ACCOUNT);
		if (!invalid_slot) {
			mutex_unlock(&mini->slots_arch_lock);
			return -ENOMEM;
		}
		mini_invalidate_memslot(mini, old, invalid_slot);
	}

	r = mini_prepare_memory_region(mini, old, new, change);
	if (r) {
		/*
		 * For DELETE/MOVE, revert the above INVALID change.  No
		 * modifications required since the original slot was preserved
		 * in the inactive slots.  Changing the active memslots also
		 * release slots_arch_lock.
		 */
		if (change == MINI_MR_DELETE || change == MINI_MR_MOVE) {
			mini_activate_memslot(mini, invalid_slot, old);
			kfree(invalid_slot);
		} else {
			mutex_unlock(&mini->slots_arch_lock);
		}
		return r;
	}

	/*
	 * For DELETE and MOVE, the working slot is now active as the INVALID
	 * version of the old slot.  MOVE is particularly special as it reuses
	 * the old slot and returns a copy of the old slot (in working_slot).
	 * For CREATE, there is no old slot.  For DELETE and FLAGS_ONLY, the
	 * old slot is detached but otherwise preserved.
	 */
	if (change == MINI_MR_CREATE)
		mini_create_memslot(mini, new);
	else if (change == MINI_MR_DELETE)
		mini_delete_memslot(mini, old, invalid_slot);
	else if (change == MINI_MR_MOVE)
		mini_move_memslot(mini, old, new, invalid_slot);
	else if (change == MINI_MR_FLAGS_ONLY)
		mini_update_flags_memslot(mini, old, new);
	else
		BUG();

	/* Free the temporary INVALID slot used for DELETE and MOVE. */
	if (change == MINI_MR_DELETE || change == MINI_MR_MOVE)
		kfree(invalid_slot);

	/*
	 * No need to refresh new->arch, changes after dropping slots_arch_lock
	 * will directly hit the final, active memslot.  Architectures are
	 * responsible for knowing that new->arch may be stale.
	 */
	mini_commit_memory_region(mini, old, new, change);

	return 0;
}

static bool mini_check_memslot_overlap(struct mini_memslots *slots, int id,
				      gfn_t start, gfn_t end)
{
	struct mini_memslot_iter iter;

	mini_for_each_memslot_in_gfn_range(&iter, slots, start, end) {
		if (iter.slot->id != id)
			return true;
	}

	return false;
}

/*
 * Allocate some memory and give it an address in the guest physical address
 * space.
 *
 * Discontiguous memory is allowed, mostly for framebuffers.
 *
 * Must be called holding mini->slots_lock for write.
 */
int __mini_set_memory_region(struct mini *mini,
			    const struct mini_userspace_memory_region *mem)
{
	struct mini_memory_slot *old, *new;
	struct mini_memslots *slots;
	enum mini_mr_change change;
	unsigned long npages;
	gfn_t base_gfn;
	int as_id, id;
	int r;

    mini_info("[mini] __mini_set_memory_region\n");

    mini_info("\t[mini] mem->slot : 0x%x\n", mem->slot);
    mini_info("\t[mini] mem->flags : 0x%x\n", mem->flags);
    mini_info("\t[mini] mem->guest_phys_addr: 0x%x\n", mem->guest_phys_addr);
    mini_info("\t[mini] mem->memory_size : 0x%x\n", mem->memory_size);
    mini_info("\t[mini] mem->userspace_addr : 0x%x\n", mem->userspace_addr);

	r = check_memory_region_flags(mem);
	if (r)
		return r;

	as_id = mem->slot >> 16;
	id = (u16)mem->slot;

    mini_info("[mini] __mini_set_memory_region_before_sanity\n");
	/* General sanity checks */
	if ((mem->memory_size & (PAGE_SIZE - 1)) ||
	    (mem->memory_size != (unsigned long)mem->memory_size))
		return -EINVAL;
	if (mem->guest_phys_addr & (PAGE_SIZE - 1))
		return -EINVAL;
	/* We can read the guest memory with __xxx_user() later on. */
	if ((mem->userspace_addr & (PAGE_SIZE - 1)) ||
	    (mem->userspace_addr != untagged_addr(mem->userspace_addr)) ||
	     !access_ok((void __user *)(unsigned long)mem->userspace_addr,
			mem->memory_size))
		return -EINVAL;
	if (as_id >= MINI_ADDRESS_SPACE_NUM || id >= MINI_MEM_SLOTS_NUM)
		return -EINVAL;
	if (mem->guest_phys_addr + mem->memory_size < mem->guest_phys_addr)
		return -EINVAL;
	if ((mem->memory_size >> PAGE_SHIFT) > MINI_MEM_MAX_NR_PAGES)
		return -EINVAL;
    mini_info("[mini] __mini_set_memory_region_after_sanity\n");

    mini_info("[mini] mini : 0x%x\n", *mini);
    mini_info("[mini] as_id : 0x%x\n", as_id);
    mini_info("[mini] id : 0x%x\n", id);

	slots = __mini_memslots(mini, as_id);
    mini_info("[mini] slots : 0x%x\n", *slots);

	/*
	 * Note, the old memslot (and the pointer itself!) may be invalidated
	 * and/or destroyed by mini_set_memslot().
	 */
    mini_info("[mini] __mini_set_memory_region_before_id_to_memslot\n");
	old = mini_id_to_memslot(slots, id);
    mini_info("[mini] __mini_set_memory_region_after_id_to_memslot\n");

	if (!mem->memory_size) {
		if (!old || !old->npages)
			return -EINVAL;

		if (WARN_ON_ONCE(mini->nr_memslot_pages < old->npages))
			return -EIO;

		return mini_set_memslot(mini, old, NULL, MINI_MR_DELETE);
	}

	base_gfn = (mem->guest_phys_addr >> PAGE_SHIFT);
	npages = (mem->memory_size >> PAGE_SHIFT);

	if (!old || !old->npages) {
		change = MINI_MR_CREATE;

		/*
		 * To simplify MINI internals, the total number of pages across
		 * all memslots must fit in an unsigned long.
		 */
		if ((mini->nr_memslot_pages + npages) < mini->nr_memslot_pages)
			return -EINVAL;
	} else { /* Modify an existing slot. */
		if ((mem->userspace_addr != old->userspace_addr) ||
		    (npages != old->npages) ||
		    ((mem->flags ^ old->flags) & MINI_MEM_READONLY))
			return -EINVAL;

		if (base_gfn != old->base_gfn)
			change = MINI_MR_MOVE;
		else if (mem->flags != old->flags)
			change = MINI_MR_FLAGS_ONLY;
		else /* Nothing to change. */
			return 0;
	}

	if ((change == MINI_MR_CREATE || change == MINI_MR_MOVE) &&
	    mini_check_memslot_overlap(slots, id, base_gfn, base_gfn + npages))
		return -EEXIST;

	/* Allocate a slot that will persist in the memslot. */
	new = kzalloc(sizeof(*new), GFP_KERNEL_ACCOUNT);
	if (!new)
		return -ENOMEM;

	new->as_id = as_id;
	new->id = id;
	new->base_gfn = base_gfn;
	new->npages = npages;
	new->flags = mem->flags;
	new->userspace_addr = mem->userspace_addr;

    mini_info("\t[__mini_set_memory_region] base_gfn : 0x%lx", new->base_gfn);
    mini_info("\t[__mini_set_memory_region] npages : 0x%lx", new->npages);
    mini_info("\t[__mini_set_memory_region] user_space_addr : 0x%lx", new->userspace_addr);

	r = mini_set_memslot(mini, old, new, change);
	if (r)
		kfree(new);
	return r;
}
EXPORT_SYMBOL_GPL(__mini_set_memory_region);

int mini_set_memory_region(struct mini *mini,
			  const struct mini_userspace_memory_region *mem)
{
	int r;

    mini_info("[mini] mini_set_memory_region\n");

	mutex_lock(&mini->slots_lock);
	r = __mini_set_memory_region(mini, mem);
	mutex_unlock(&mini->slots_lock);
	return r;
}
EXPORT_SYMBOL_GPL(mini_set_memory_region);

static bool mini_page_in_dirty_ring(struct mini *mini, unsigned long pgoff)
{
#ifdef CONFIG_HAVE_MINI_DIRTY_RING
	return (pgoff >= MINI_DIRTY_LOG_PAGE_OFFSET) &&
	    (pgoff < MINI_DIRTY_LOG_PAGE_OFFSET +
	     mini->dirty_ring_size / PAGE_SIZE);
#else
	return false;
#endif
}

static vm_fault_t mini_vcpu_fault(struct vm_fault *vmf)
{
	struct mini_vcpu *vcpu = vmf->vma->vm_file->private_data;
	struct page *page;

	if (vmf->pgoff == 0)
		page = virt_to_page(vcpu->run);
#ifdef CONFIG_X86
	else if (vmf->pgoff == MINI_PIO_PAGE_OFFSET)
		page = virt_to_page(vcpu->arch.pio_data);
#endif
#ifdef CONFIG_MINI_MMIO
	else if (vmf->pgoff == MINI_COALESCED_MMIO_PAGE_OFFSET)
		page = virt_to_page(vcpu->mini->coalesced_mmio_ring);
#endif
	else if (mini_page_in_dirty_ring(vcpu->mini, vmf->pgoff))
		page = mini_dirty_ring_get_page(
		    &vcpu->dirty_ring,
		    vmf->pgoff - MINI_DIRTY_LOG_PAGE_OFFSET);
	else
		return mini_arch_vcpu_fault(vcpu, vmf);
	get_page(page);
	vmf->page = page;
	return 0;
}

static const struct vm_operations_struct mini_vcpu_vm_ops = {
	.fault = mini_vcpu_fault,
};

static int mini_vm_ioctl_set_memory_region(struct mini *mini,
					  struct mini_userspace_memory_region *mem)
{
	if ((u16)mem->slot >= MINI_USER_MEM_SLOTS)
		return -EINVAL;

	return mini_set_memory_region(mini, mem);
}

static int mini_vcpu_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct mini_vcpu *vcpu = file->private_data;
	unsigned long pages = vma_pages(vma);

	if ((mini_page_in_dirty_ring(vcpu->mini, vma->vm_pgoff) ||
	     mini_page_in_dirty_ring(vcpu->mini, vma->vm_pgoff + pages - 1)) &&
	    ((vma->vm_flags & VM_EXEC) || !(vma->vm_flags & VM_SHARED)))
		return -EINVAL;

	vma->vm_ops = &mini_vcpu_vm_ops;
	return 0;
}

static int mini_vcpu_release(struct inode *inode, struct file *filp)
{
	struct mini_vcpu *vcpu = filp->private_data;

	//kvm_put_kvm(vcpu->kvm);
	return 0;
}

static const struct file_operations mini_vcpu_fops = {
	.release        = mini_vcpu_release,
	.unlocked_ioctl = mini_vcpu_ioctl,
	.mmap           = mini_vcpu_mmap,
	.llseek		= noop_llseek,
	MINI_COMPAT(mini_vcpu_compat_ioctl),
};

static int create_vcpu_fd(struct mini_vcpu *vcpu)
{
	char name[8 + 1 + ITOA_MAX_LEN + 1];

    mini_info("[mini] create_vcpu_fd\n");

	snprintf(name, sizeof(name), "mini-vcpu:%d", vcpu->vcpu_id);
	return anon_inode_getfd(name, &mini_vcpu_fops, vcpu, O_RDWR | O_CLOEXEC);
}

static int mini_vm_ioctl_create_vcpu(struct mini *mini, u32 id)
{
    int r;
    struct mini_vcpu *vcpu;
    struct page *page;

    mini_info("[mini] mini_vm_ioctl_create_vcpu\n");

    if (id >= MINI_MAX_VCPU_IDS)
        return -EINVAL;

    mutex_lock(&mini->lock);
    if (mini->created_vcpus >= mini->max_vcpus) {
        mutex_unlock(&mini->lock);
        return -EINVAL;
    }

    r = 0;
    
    mini->created_vcpus++;
    mutex_unlock(&mini->lock);

    mini_info("[mini] zalloc\n");
    vcpu = kmem_cache_zalloc(mini_vcpu_cache, GFP_KERNEL_ACCOUNT);
    if(!vcpu) {
        r = -ENOMEM;
        //goto vcpu_decrement;
    }
    mini_info("[mini] cache_zalloc\n");

    //BUILD_BUG_ON(sizeof(struct mini_run) > PAGE_SIZE);
    page = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
    if(!page) {
        r = -ENOMEM;
        //goto vcpu_free;
    }
    mini_info("[mini] alloc_page\n");
    vcpu->run = page_address(page);

    r = mini_arch_vcpu_create(vcpu);
    if(r) {
        r = -ENOMEM;
        //goto vcpu_free_run_page;
    }

	r = create_vcpu_fd(vcpu);
	if (r < 0) {
        r = -EINVAL;
        mini_info("[mini] ERROR fd\n");
    }
    return r;
}

static long mini_vm_ioctl(struct file *flip,
            unsigned int ioctl, unsigned long arg)
{
    struct mini *mini = flip->private_data;
	void __user *argp = (void __user *)arg;
    int r;

    mini_info("[mini] mini_vm_ioctl\n");

    switch(ioctl) {
	case MINI_CREATE_VCPU:
		r = mini_vm_ioctl_create_vcpu(mini, arg);
		break;
    //case MINI_ALLOC:

    //    break;
	case MINI_SET_USER_MEMORY_REGION: {
		struct mini_userspace_memory_region mini_userspace_mem;

		r = -EFAULT;
		if (copy_from_user(&mini_userspace_mem, argp,
						sizeof(mini_userspace_mem)))
			goto out;

		r = mini_vm_ioctl_set_memory_region(mini, &mini_userspace_mem);
		break;
	}
    case MINI_FREE: 
        break;
    case MINI_ENTER:
        mini_arch_enter(mini);
        csr_write(CSR_HSTATUS, csr_read(CSR_HSTATUS) | HSTATUS_HU);
        mini_info("MINI_ENTER : 0x%x\n", csr_read(CSR_HSTATUS));

        /*
        char data[10] = "abcd";
        mini_write_guest(mini, 0x80000000, (void *)data, 10); 
        mini_info("[mini] write end PAGE_SIZE : 0x%x VM_ID : %d\n", PAGE_SIZE, mini->arch.vmid);
        */ 

        // writing test end
        
        /*
        unsigned long val, guest_addr;
        guest_addr = 0x897c4000;
        mini_info("val : 0x%lx\n", val);
        asm volatile(HLV_W(%[val], %[addr]) :[val] "=&r" (val): [addr] "r" (guest_addr) );
        mini_info("val : 0x%lx\n", val);
        */

        /*
        unsigned long val, guest_addr;
        guest_addr = 0x80000000;
        mini_info("val : 0x%lx\n", val);
        asm volatile(HLV_W(%[val], %[addr]) :[val] "=&r" (val): [addr] "r" (guest_addr) );
        mini_info("val : 0x%lx\n", val);
        */

        //mini_info("HLV_W : 0x%08x\n", HLV_W(%[val], %[add]));

        break;
    case MINI_EXIT:
        csr_write(CSR_HSTATUS, csr_read(CSR_HSTATUS) & !HSTATUS_HU);
        mini_info("MINI_EXIT 0x%x\n", csr_read(CSR_HSTATUS));
        break;
    }
    return r;

out:
    return r;
}

/*
static int __mini_write_guest_page(struct mini *mini,
				  struct mini_memory_slot *memslot, gfn_t gfn,
			          const void *data, int offset, int len)
{
	int r;
	unsigned long addr;

    mini_info ("[mini] __mini_write_guest_page\n");

	addr = gfn_to_hva_memslot(memslot, gfn);
	if (mini_is_error_hva(addr))
		return -EFAULT;
	r = __copy_to_user((void __user *)addr + offset, data, len);
	if (r)
		return -EFAULT;
	mark_page_dirty_in_slot(mini, memslot, gfn);
    mini_info("\t[mini] gfn : 0x%x\toffset : 0x%x\n", gfn, offset);
    mini_info("\t[mini] data : %s\n", data);
	return 0;
}

int mini_write_guest_page(struct mini *mini, gfn_t gfn,
			 const void *data, int offset, int len)
{
	struct mini_memory_slot *slot = gfn_to_memslot(mini, gfn);

	return __mini_write_guest_page(mini, slot, gfn, data, offset, len);
}
EXPORT_SYMBOL_GPL(mini_write_guest_page);

int mini_write_guest(struct mini *mini, gpa_t gpa, const void *data,
		    unsigned long len)
{
	gfn_t gfn = gpa >> PAGE_SHIFT;
	int seg;
	int offset = offset_in_page(gpa);
	int ret;

	while ((seg = next_segment(len, offset)) != 0) {
		ret = mini_write_guest_page(mini, gfn, data, offset, seg);
		if (ret < 0)
			return ret;
		offset = 0;
		len -= seg;
		data += seg;
		++gfn;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(mini_write_guest);
*/

static inline struct mini_memory_slot *
try_get_memslot(struct mini_memory_slot *slot, gfn_t gfn)
{
	if (!slot)
		return NULL;

	if (gfn >= slot->base_gfn && gfn < slot->base_gfn + slot->npages)
		return slot;
	else
		return NULL;
}

static inline struct mini_memory_slot *
search_memslots(struct mini_memslots *slots, gfn_t gfn, bool approx)
{
	struct mini_memory_slot *slot;
	struct rb_node *node;
	int idx = slots->node_idx;

	slot = NULL;
	for (node = slots->gfn_tree.rb_node; node; ) {
		slot = container_of(node, struct mini_memory_slot, gfn_node[idx]);
		if (gfn >= slot->base_gfn) {
			if (gfn < slot->base_gfn + slot->npages)
				return slot;
			node = node->rb_right;
		} else
			node = node->rb_left;
	}

	return approx ? slot : NULL;
}

static inline struct mini_memory_slot *
____gfn_to_memslot(struct mini_memslots *slots, gfn_t gfn, bool approx)
{
	struct mini_memory_slot *slot;

	slot = (struct mini_memory_slot *)atomic_long_read(&slots->last_used_slot);
	slot = try_get_memslot(slot, gfn);
	if (slot)
		return slot;

	slot = search_memslots(slots, gfn, approx);
	if (slot) {
		atomic_long_set(&slots->last_used_slot, (unsigned long)slot);
		return slot;
	}

	return NULL;
}

/*
 * __gfn_to_memslot() and its descendants are here to allow arch code to inline
 * the lookups in hot paths.  gfn_to_memslot() itself isn't here as an inline
 * because that would bloat other code too much.
 */
static inline struct mini_memory_slot *
__gfn_to_memslot(struct mini_memslots *slots, gfn_t gfn)
{
	return ____gfn_to_memslot(slots, gfn, false);
}

static inline unsigned long
__gfn_to_hva_memslot(const struct mini_memory_slot *slot, gfn_t gfn)
{
	/*
	 * The index was checked originally in search_memslots.  To avoid
	 * that a malicious guest builds a Spectre gadget out of e.g. page
	 * table walks, do not let the processor speculate loads outside
	 * the guest's registered memslots.
	 */
	unsigned long offset = gfn - slot->base_gfn;
	offset = array_index_nospec(offset, slot->npages);
	return slot->userspace_addr + offset * PAGE_SIZE;
}

static inline int memslot_id(struct mini *mini, gfn_t gfn)
{
	return mini_gfn_to_memslot(mini, gfn)->id;
}

struct mini_memory_slot *gfn_to_memslot(struct mini *mini, gfn_t gfn)
{
	return __gfn_to_memslot(mini_memslots(mini), gfn);
}

static bool memslot_is_readonly(const struct mini_memory_slot *slot)
{
	return slot->flags & MINI_MEM_READONLY;
}

static unsigned long __gfn_to_hva_many(const struct mini_memory_slot *slot, gfn_t gfn,
				       gfn_t *nr_pages, bool write)
{
	if (!slot || slot->flags & MINI_MEMSLOT_INVALID)
		return MINI_HVA_ERR_BAD;

	if (memslot_is_readonly(slot) && write)
		return MINI_HVA_ERR_RO_BAD;

	if (nr_pages)
		*nr_pages = slot->npages - (gfn - slot->base_gfn);

	return __gfn_to_hva_memslot(slot, gfn);
}

static bool vma_is_valid(struct vm_area_struct *vma, bool write_fault)
{
	if (unlikely(!(vma->vm_flags & VM_READ)))
		return false;

	if (write_fault && (unlikely(!(vma->vm_flags & VM_WRITE))))
		return false;

	return true;
}

static int mini_try_get_pfn(mini_pfn_t pfn)
{
	struct page *page = mini_pfn_to_refcounted_page(pfn);

	if (!page)
		return 1;

	return get_page_unless_zero(page);
}

unsigned long gfn_to_hva_memslot_prot(struct mini_memory_slot *slot,
				      gfn_t gfn, bool *writable)
{
	unsigned long hva = __gfn_to_hva_many(slot, gfn, NULL, false);

	if (!mini_is_error_hva(hva) && writable)
		*writable = !memslot_is_readonly(slot);

	return hva;
}
/*
 * The fast path to get the writable pfn which will be stored in @pfn,
 * true indicates success, otherwise false is returned.  It's also the
 * only part that runs if we can in atomic context.
 */
static bool hva_to_pfn_fast(unsigned long addr, bool write_fault,
			    bool *writable, mini_pfn_t *pfn)
{
	struct page *page[1];

	/*
	 * Fast pin a writable pfn only if it is a write fault request
	 * or the caller allows to map a writable pfn for a read fault
	 * request.
	 */
	if (!(write_fault || writable))
		return false;

	if (get_user_page_fast_only(addr, FOLL_WRITE, page)) {
		*pfn = page_to_pfn(page[0]);

		if (writable)
			*writable = true;
		return true;
	}

	return false;
}

static inline int check_user_page_hwpoison(unsigned long addr)
{
	int rc, flags = FOLL_HWPOISON | FOLL_WRITE;

	rc = get_user_pages(addr, 1, flags, NULL, NULL);
	return rc == -EHWPOISON;
}

/*
 * The slow path to get the pfn of the specified host virtual address,
 * 1 indicates success, -errno is returned if error is detected.
 */
static int hva_to_pfn_slow(unsigned long addr, bool *async, bool write_fault,
			   bool interruptible, bool *writable, mini_pfn_t *pfn)
{
	unsigned int flags = FOLL_HWPOISON;
	struct page *page;
	int npages;

	might_sleep();

	if (writable)
		*writable = write_fault;

	if (write_fault)
		flags |= FOLL_WRITE;
	if (async)
		flags |= FOLL_NOWAIT;
	if (interruptible)
		flags |= FOLL_INTERRUPTIBLE;

	npages = get_user_pages_unlocked(addr, 1, &page, flags);
	if (npages != 1)
		return npages;

	/* map read fault as writable if possible */
	if (unlikely(!write_fault) && writable) {
		struct page *wpage;

		if (get_user_page_fast_only(addr, FOLL_WRITE, &wpage)) {
			*writable = true;
			put_page(page);
			page = wpage;
		}
	}
	*pfn = page_to_pfn(page);
	return npages;
}

static int hva_to_pfn_remapped(struct vm_area_struct *vma,
			       unsigned long addr, bool write_fault,
			       bool *writable, mini_pfn_t *p_pfn)
{
	mini_pfn_t pfn;
	pte_t *ptep;
	spinlock_t *ptl;
	int r;

	r = follow_pte(vma->vm_mm, addr, &ptep, &ptl);
	if (r) {
		/*
		 * get_user_pages fails for VM_IO and VM_PFNMAP vmas and does
		 * not call the fault handler, so do it here.
		 */
		bool unlocked = false;
		r = fixup_user_fault(current->mm, addr,
				     (write_fault ? FAULT_FLAG_WRITE : 0),
				     &unlocked);
		if (unlocked)
			return -EAGAIN;
		if (r)
			return r;

		r = follow_pte(vma->vm_mm, addr, &ptep, &ptl);
		if (r)
			return r;
	}

	if (write_fault && !pte_write(*ptep)) {
		pfn = MINI_PFN_ERR_RO_FAULT;
		goto out;
	}

	if (writable)
		*writable = pte_write(*ptep);
	pfn = pte_pfn(*ptep);

	/*
	 * Get a reference here because callers of *hva_to_pfn* and
	 * *gfn_to_pfn* ultimately call mini_release_pfn_clean on the
	 * returned pfn.  This is only needed if the VMA has VM_MIXEDMAP
	 * set, but the mini_try_get_pfn/mini_release_pfn_clean pair will
	 * simply do nothing for reserved pfns.
	 *
	 * Whoever called remap_pfn_range is also going to call e.g.
	 * unmap_mapping_range before the underlying pages are freed,
	 * causing a call to our MMU notifier.
	 *
	 * Certain IO or PFNMAP mappings can be backed with valid
	 * struct pages, but be allocated without refcounting e.g.,
	 * tail pages of non-compound higher order allocations, which
	 * would then underflow the refcount when the caller does the
	 * required put_page. Don't allow those pages here.
	 */ 
	if (!mini_try_get_pfn(pfn))
		r = -EFAULT;

out:
	pte_unmap_unlock(ptep, ptl);
	*p_pfn = pfn;

	return r;
}
/*
 * Pin guest page in memory and return its pfn.
 * @addr: host virtual address which maps memory to the guest
 * @atomic: whether this function can sleep
 * @interruptible: whether the process can be interrupted by non-fatal signals
 * @async: whether this function need to wait IO complete if the
 *         host page is not in the memory
 * @write_fault: whether we should get a writable host page
 * @writable: whether it allows to map a writable host page for !@write_fault
 *
 * The function will map a writable host page for these two cases:
 * 1): @write_fault = true
 * 2): @write_fault = false && @writable, @writable will tell the caller
 *     whether the mapping is writable.
 */
mini_pfn_t hva_to_pfn(unsigned long addr, bool atomic, bool interruptible,
		     bool *async, bool write_fault, bool *writable)
{
	struct vm_area_struct *vma;
	mini_pfn_t pfn;
	int npages, r;

	/* we can do it either atomically or asynchronously, not both */
	BUG_ON(atomic && async);

	if (hva_to_pfn_fast(addr, write_fault, writable, &pfn))
		return pfn;

	if (atomic)
		return MINI_PFN_ERR_FAULT;

	npages = hva_to_pfn_slow(addr, async, write_fault, interruptible,
				 writable, &pfn);
	if (npages == 1)
		return pfn;
	if (npages == -EINTR)
		return MINI_PFN_ERR_SIGPENDING;

	mmap_read_lock(current->mm);
	if (npages == -EHWPOISON ||
	      (!async && check_user_page_hwpoison(addr))) {
		pfn = MINI_PFN_ERR_HWPOISON;
		goto exit;
	}

retry:
	vma = vma_lookup(current->mm, addr);

	if (vma == NULL)
		pfn = MINI_PFN_ERR_FAULT;
	else if (vma->vm_flags & (VM_IO | VM_PFNMAP)) {
		r = hva_to_pfn_remapped(vma, addr, write_fault, writable, &pfn);
		if (r == -EAGAIN)
			goto retry;
		if (r < 0)
			pfn = MINI_PFN_ERR_FAULT;
	} else {
		if (async && vma_is_valid(vma, write_fault))
			*async = true;
		pfn = MINI_PFN_ERR_FAULT;
	}
exit:
	mmap_read_unlock(current->mm);
	return pfn;
}

mini_pfn_t mini__gfn_to_pfn_memslot(const struct mini_memory_slot *slot, gfn_t gfn,
			       bool atomic, bool interruptible, bool *async,
			       bool write_fault, bool *writable, hva_t *hva)
{
	unsigned long addr = __gfn_to_hva_many(slot, gfn, NULL, write_fault);

	if (hva)
		*hva = addr;

	if (addr == MINI_HVA_ERR_RO_BAD) {
		if (writable)
			*writable = false;
		return MINI_PFN_ERR_RO_FAULT;
	}

	if (mini_is_error_hva(addr)) {
		if (writable)
			*writable = false;
		return MINI_PFN_NOSLOT;
	}

	/* Do not map writable pfn in the readonly memslot. */
	if (writable && memslot_is_readonly(slot)) {
		*writable = false;
		writable = NULL;
	}

	return hva_to_pfn(addr, atomic, interruptible, async, write_fault,
			  writable);
}
EXPORT_SYMBOL_GPL(mini__gfn_to_pfn_memslot);

mini_pfn_t mini_gfn_to_pfn_prot(struct mini *mini, gfn_t gfn, bool write_fault,
		      bool *writable)
{
	return mini__gfn_to_pfn_memslot(gfn_to_memslot(mini, gfn), gfn, false, false,
				    NULL, write_fault, writable, NULL);
}
EXPORT_SYMBOL_GPL(mini_gfn_to_pfn_prot);

static const struct file_operations mini_vm_fops = {
    .unlocked_ioctl = mini_vm_ioctl,
	.llseek		= noop_llseek,
};

static int mini_dev_ioctl_create_vm(unsigned long type)
{
    char fdname[ITOA_MAX_LEN + 1];
    int r, fd;
    struct mini *mini;
    struct file *file;

    fd = get_unused_fd_flags(O_CLOEXEC);
    if(fd < 0)
        return fd;

    mini_info("mini_dev_ioctl_create_vm %d \n", fd);

    snprintf(fdname, sizeof(fdname), "%d", fd);

    mini = mini_create_vm(type, fdname);
    if(IS_ERR(mini)) {
        r = PTR_ERR(mini);
    }

    file = anon_inode_getfile("mini-vm", &mini_vm_fops, mini, O_RDWR);
    if(IS_ERR(file)) {
        r = PTR_ERR(file);
    }

    fd_install(fd, file);
    return fd;

}
static long mini_dev_ioctl(struct file *flip, 
            unsigned int ioctl, unsigned long arg)
{
    int r = -EINVAL;
    mini_info("mini_dev_ioctl, %x\n", ioctl);


    switch(ioctl) {
    case MINI_CREATE_VM: 
        r = mini_dev_ioctl_create_vm(arg);
        break;
    case MINI_DEST_VM:
        break;
    default:
        return 0;
    }

    return r;
}

static struct file_operations mini_chardev_ops = {
    .unlocked_ioctl = mini_dev_ioctl,
    .llseek = noop_llseek,
};
void mini_exit(void)
{
    debugfs_remove_recursive(mini_debugfs_dir);
}

bool mini_vcpu_wake_up(struct mini_vcpu *vcpu)
{
	if (__mini_vcpu_wake_up(vcpu)) {
		WRITE_ONCE(vcpu->ready, true);
		++vcpu->stat.generic.halt_wakeup;
		return true;
	}

	return false;
}
EXPORT_SYMBOL_GPL(mini_vcpu_wake_up);

static ssize_t mini_vcpu_stats_read(struct file *file, char __user *user_buffer,
			      size_t size, loff_t *offset)
{
	struct mini_vcpu *vcpu = file->private_data;

	return mini_stats_read(vcpu->stats_id, &mini_vcpu_stats_header,
			&mini_vcpu_stats_desc[0], &vcpu->stat,
			sizeof(vcpu->stat), user_buffer, size, offset);
}

static const struct file_operations mini_vcpu_stats_fops = {
	.read = mini_vcpu_stats_read,
	.llseek = noop_llseek,
};

static long mini_vcpu_ioctl(struct file *filp,
			   unsigned int ioctl, unsigned long arg)
{
    struct mini_vcpu *vcpu = filp->private_data;
    void __user *argv = (void __user *)arg;
    int r = 0;

    mini_info("[mini] mini_vcpu_ioctl\n");


	if (vcpu->mini->mm != current->mm || vcpu->mini->vm_dead)
		return -EIO;
    mini_info("[mini] mm\n");

	if (unlikely(_IOC_TYPE(ioctl) != MINIIO))
		return -EINVAL;
    mini_info("[mini] MINIIO\n");

	switch (ioctl) {
        case MINI_ALLOC: 
            mini_info("[mini] MINI_ALLOC\n");
            struct mini *mini = vcpu->mini;

            // GPA 2 HPA mapping setup
            bool writable = true;
            unsigned long vma_pagesize;
            gpa_t gpa = 0x80000000;
            gfn_t gfn = gpa >> (PAGE_SHIFT);
            struct mini_memory_slot *memslot = gfn_to_memslot(mini, gfn);
            int count = 0;

        // GPA 2 HPA mapping 

            // GPA 2 HPA mapping 
            while(count < memslot->npages) { 
                mini_pfn_t hfn = mini_gfn_to_pfn_prot(mini, gfn, true, &writable);
                phys_addr_t hpa = hfn << PAGE_SHIFT;
                gfn = gpa >> (PAGE_SHIFT);
                unsigned long hva = gfn_to_hva_memslot_prot(memslot, gfn, &writable);

                //mini_info("prog : %d / %d\n", count+1, memslot->npages);
                //mini_info("[mini] gpa : 0x%x, gfn : 0x%x, hva : 0x%lx, hfn : 0x%x, hpa : 0x%x\n",
                //        gpa, gfn, hva, hfn, hpa);
                //mini_info("[mini] pages %d\taddr 0x%lx\t id %d\n", memslot->npages, memslot->userspace_addr, memslot->id);

                //uintptr_t end_va = kernel_map.virt_addr + 0x40000;

                mini_riscv_gstage_map(vcpu, memslot, gpa, hva, true); 

                gpa += PAGE_SIZE;
                count ++;
            } // while end
                            
            break;
        default:
            mini_info("[mini] MINI_ALLOC\n");
            break;
    }

    return r;
}
int mini_init(unsigned vcpu_size, unsigned vcpu_align, struct module *module)
{
    mini_info("mini_init %x %x\n", vcpu_size, vcpu_align);

    major = register_chrdev(0, DEVICE_NAME, &mini_chardev_ops);
    if(major < 0) {
        mini_info("Registering char device failed with %d\n", major);
        return major;
    }

    mini_info("Assigned major number : %d\n", major);

	if (!vcpu_align)
		vcpu_align = __alignof__(struct mini_vcpu);
	mini_vcpu_cache =
		kmem_cache_create_usercopy("mini_vcpu", vcpu_size, vcpu_align,
					   SLAB_ACCOUNT,
					   offsetof(struct mini_vcpu, arch),
					   offsetofend(struct mini_vcpu, stats_id)
					   - offsetof(struct mini_vcpu, arch),
					   NULL);
	if (!mini_vcpu_cache) {
        mini_info("ERROR!\n");   
        return -1;
    }

    cls = class_create(DEVICE_NAME);
    device_create(cls, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);

    mini_info("Device created on /dev/%s\n", DEVICE_NAME);

    return 0;
}
EXPORT_SYMBOL_GPL(mini_init);
