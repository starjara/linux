#include <linux/mini_host.h>
//#include <linux/mini.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/vmalloc.h>
#include <linux/debugfs.h>
#include <linux/file.h>
#include <linux/cpumask.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/types.h>
#include <linux/swap.h>
//#include <linux/mini_types.h>
#include <linux/fs.h>
#include <linux/anon_inodes.h>
#include <linux/mman.h>

#include <asm/processor.h>
#include <asm/ioctl.h>
#include <linux/uaccess.h>

#include "mini_mm.h"
#include "../kvm/kvm_mm.h"

#include <linux/kvm.h>
#include <linux/kvm_host.h>

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
 * - If the open has been done by a 64bit task, and the KVM fd
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

struct page *mini_pfn_to_refcounted_page(kvm_pfn_t pfn)
{
	struct page *page;

	if (!pfn_valid(pfn))
		return NULL;

	page = pfn_to_page(pfn);
	if (!PageReserved(page))
		return page;

	// The ZERO_PAGE(s) is marked PG_reserved, but is refcounted.
	if (is_zero_pfn(pfn))
		return page;

	 //ZONE_DEVICE pages currently set PG_reserved, but from a refcounting
	 //perspective they are "normal" pages, albeit with slightly different
	 //usage rules.
     
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

	if (likely(!(req & KVM_REQUEST_NO_ACTION)))
		__mini_make_request(req, vcpu);

	if (!(req & KVM_REQUEST_NO_WAKEUP) && mini_vcpu_wake_up(vcpu))
		return;

	/*
	 * Note, the vCPU could get migrated to a different pCPU at any point
	 * after mini_request_needs_ipi(), which could result in sending an IPI
	 * to the previous pCPU.  But, that's OK because the purpose of the IPI
	 * is to ensure the vCPU returns to OUTSIDE_GUEST_MODE, which is
	 * satisfied if the vCPU migrates. Entering READING_SHADOW_PAGE_TABLES
	 * after this point is also OK, as the requirement is only that KVM wait
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

	for_each_set_bit(i, vcpu_bitmap, KVM_MAX_VCPUS) {
		vcpu = mini_get_vcpu(mini, i);
		if (!vcpu)
			continue;
		mini_make_vcpu_request(vcpu, req, cpus, me);
	}

	called = mini_kick_many_cpus(cpus, !!(req & KVM_REQUEST_WAIT));
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

	kvm_for_each_vcpu(i, vcpu, mini) {
		if (vcpu == except)
			continue;
		mini_make_vcpu_request(vcpu, req, cpus, me);
	}

	called = mini_kick_many_cpus(cpus, !!(req & KVM_REQUEST_WAIT));
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
	    || mini_make_all_cpus_request(mini, KVM_REQ_TLB_FLUSH))
		++mini->stat.generic.remote_tlb_flush;
}
EXPORT_SYMBOL_GPL(mini_flush_remote_tlbs);
#endif

static void mini_flush_shadow_all(struct mini *mini)
{
	mini_arch_flush_shadow_all(mini);
	mini_arch_guest_memory_reclaimed(mini);
}

#ifdef KVM_ARCH_NR_OBJS_PER_MEMORY_CACHE
static inline void *mmu_memory_cache_alloc_obj(struct kvm_mmu_memory_cache *mc,
					       gfp_t gfp_flags)
{
	gfp_flags |= mc->gfp_zero;

	if (mc->kmem_cache)
		return kmem_cache_alloc(mc->kmem_cache, gfp_flags);
	else
		return (void *)__get_free_page(gfp_flags);
}

int __mini_mmu_topup_memory_cache(struct kvm_mmu_memory_cache *mc, int capacity, int min)
{
	gfp_t gfp = mc->gfp_custom ? mc->gfp_custom : GFP_KERNEL_ACCOUNT;
	void *obj;

    //mini_info("[mini] mini_topup_memory_cache\n");

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

int kvm_mmu_topup_memory_cache(struct kvm_mmu_memory_cache *mc, int min)
{
    //mini_info("[mini] kvm_mmu_topup_memory_cache\n");
	return __mini_mmu_topup_memory_cache(mc, KVM_ARCH_NR_OBJS_PER_MEMORY_CACHE, min);
}

int mini_mmu_memory_cache_nr_free_objects(struct kvm_mmu_memory_cache *mc)
{
    mini_info("[mini] mini_mmu_memory_cache_nr_free_objects\n");
	return mc->nobjs;
}

void kvm_mmu_free_memory_cache(struct kvm_mmu_memory_cache *mc)
{
    mini_info("[mini] kvm_mmu_free_memory_cache\n");
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

void *mini_mmu_memory_cache_alloc(struct kvm_mmu_memory_cache *mc)
{
	void *p;

    //mini_info ("[mini] mini_mmu_memory_cache_alloc\n");
	if (WARN_ON(!mc->nobjs))
		p = mmu_memory_cache_alloc_obj(mc, GFP_ATOMIC | __GFP_ACCOUNT);
	else
		p = mc->objects[--mc->nobjs];
	BUG_ON(!p);
	return p;
}
#endif

/*
 * Allocation size is twice as large as the actual dirty bitmap size.
 * See mini_vm_ioctl_get_dirty_log() why this is needed.
 */
static int mini_alloc_dirty_bitmap(struct kvm_memory_slot *memslot)
{
	unsigned long dirty_bytes = mini_dirty_bitmap_bytes(memslot);

	memslot->dirty_bitmap = __vcalloc(2, dirty_bytes, GFP_KERNEL_ACCOUNT);
	if (!memslot->dirty_bitmap)
		return -ENOMEM;

	return 0;
}

static void mini_destroy_dirty_bitmap(struct kvm_memory_slot *memslot)
{
	if (!memslot->dirty_bitmap)
		return;

	kvfree(memslot->dirty_bitmap);
	memslot->dirty_bitmap = NULL;
}

/* This does not remove the slot from struct kvm_memslots data structures */
static void mini_free_memslot(struct mini *mini, struct kvm_memory_slot *slot)
{
	mini_destroy_dirty_bitmap(slot);

	mini_arch_free_memslot(mini, slot);

	kfree(slot);
}

static void mini_free_memslots(struct mini *mini, struct kvm_memslots *slots)
{
	struct hlist_node *idnode;
	struct kvm_memory_slot *memslot;
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

static void mini_vcpu_destroy(struct mini_vcpu *vcpu)
{
	mini_arch_vcpu_destroy(vcpu);
	mini_dirty_ring_free(&vcpu->dirty_ring);

    mini_info("vcpu destroy\n");
	/*
	 * No need for rcu_read_lock as VCPU_RUN is the only place that changes
	 * the vcpu->pid pointer, and at destruction time all file descriptors
	 * are already gone.
	 */
	put_pid(rcu_dereference_protected(vcpu->pid, 1));

	free_page((unsigned long)vcpu->run);
	kmem_cache_free(mini_vcpu_cache, vcpu);
}

void mini_destroy_vcpus(struct mini *mini)
{
	unsigned long i;
	struct mini_vcpu *vcpu;

    mini_info("mini_destroy_vcpus\n");

	mini_info("%d\n", (atomic_read(&mini->online_vcpus) - 1));
	xa_for_each_range(&mini->vcpu_array, i, vcpu, 0, 2) {
			  //(atomic_read(&mini->online_vcpus) - 1)) {
        mini_info("%d\n", i);
        mini_vcpu_destroy(vcpu);
        xa_erase(&mini->vcpu_array, i);
    }

    /*
	kvm_for_each_vcpu(i, vcpu, mini) {
		mini_vcpu_destroy(vcpu);
		xa_erase(&mini->vcpu_array, i);
	}
    */

	atomic_set(&mini->online_vcpus, 0);
}

static int check_memory_region_flags(const struct kvm_userspace_memory_region *mem)
{
	u32 valid_flags = KVM_MEM_LOG_DIRTY_PAGES;

#ifdef __KVM_HAVE_READONLY_MEM
	valid_flags |= KVM_MEM_READONLY;
#endif

	if (mem->flags & ~valid_flags)
		return -EINVAL;

	return 0;
}

#if defined(CONFIG_MMU_NOTIFIER) && defined(KVM_ARCH_WANT_MMU_NOTIFIER)
static inline struct mini *mmu_notifier_to_mini(struct mmu_notifier *mn)
{
	return container_of(mn, struct mini, mmu_notifier);
}
__weak void mini_arch_mmu_notifier_invalidate_range(struct mini *mini,
						   unsigned long start, unsigned long end)
{
}

static void mini_mmu_notifier_release(struct mmu_notifier *mn,
				     struct mm_struct *mm)
{
	struct mini *mini = mmu_notifier_to_mini(mn);
	int idx;

	idx = srcu_read_lock(&mini->srcu);
	mini_flush_shadow_all(mini);
	srcu_read_unlock(&mini->srcu, idx);
}

static const struct mmu_notifier_ops mini_mmu_notifier_ops = {
    /*
	.invalidate_range	= kvm_mmu_notifier_invalidate_range,
	.invalidate_range_start	= kvm_mmu_notifier_invalidate_range_start,
	.invalidate_range_end	= kvm_mmu_notifier_invalidate_range_end,
	.clear_flush_young	= kvm_mmu_notifier_clear_flush_young,
	.clear_young		= kvm_mmu_notifier_clear_young,
	.test_young		= kvm_mmu_notifier_test_young,
	.change_pte		= kvm_mmu_notifier_change_pte,
    */
	.release		= mini_mmu_notifier_release,
};

static int mini_init_mmu_notifier(struct mini *mini)
{
	mini->mmu_notifier.ops = &mini_mmu_notifier_ops;
	return mmu_notifier_register(&mini->mmu_notifier, current->mm);
}
#else  /* !(CONFIG_MMU_NOTIFIER && KVM_ARCH_WANT_MMU_NOTIFIER) */

static int mini_init_mmu_notifier(struct mini *mini)
{
	return 0;
}

#endif /* CONFIG_MMU_NOTIFIER && KVM_ARCH_WANT_MMU_NOTIFIER */

static struct kvm_memslots *mini_get_inactive_memslots(struct mini *mini, int as_id)
{
	struct kvm_memslots *active = __mini_memslots(mini, as_id);
	int node_idx_inactive = active->node_idx ^ 1;

	return &mini->__memslots[as_id][node_idx_inactive];
}

static void mini_swap_active_memslots(struct mini *mini, int as_id)
{
	struct kvm_memslots *slots = mini_get_inactive_memslots(mini, as_id);
    mini_info("[mini] mini_swap_active_memslots\n");

	/* Grab the generation from the activate memslots. */
	u64 gen = __mini_memslots(mini, as_id)->generation;

	WARN_ON(gen & KVM_MEMSLOT_GEN_UPDATE_IN_PROGRESS);
	slots->generation = gen | KVM_MEMSLOT_GEN_UPDATE_IN_PROGRESS;

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
	gen = slots->generation & ~KVM_MEMSLOT_GEN_UPDATE_IN_PROGRESS;

	/*
	 * Generations must be unique even across address spaces.  We do not need
	 * a global counter for that, instead the generation space is evenly split
	 * across address spaces.  For example, with two address spaces, address
	 * space 0 will use generations 0, 2, 4, ... while address space 1 will
	 * use generations 1, 3, 5, ...
	 */
	gen += KVM_ADDRESS_SPACE_NUM;

	mini_arch_memslots_updated(mini, gen);

	slots->generation = gen;
}

static void mini_copy_memslot(struct kvm_memory_slot *dest,
			     const struct kvm_memory_slot *src)
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
    struct kvm_memslots *slots;
    int r = -ENOMEM;
    int i, j;

    mini_info("[mini] mini : 0x%x\n", *mini);

    if(!mini)
        return ERR_PTR(-ENOMEM);

    mini_info("[mini] mini_create_vm\n");

    __module_get(mini_chardev_ops.owner);

	KVM_MMU_LOCK_INIT(mini);
	//mmgrab(current->mm);
	//mini->mm = current->mm;
	//mini_eventfd_init(mini);
	mutex_init(&mini->lock);
	//mutex_init(&mini->irq_lock);
	mutex_init(&mini->slots_lock);
	mutex_init(&mini->slots_arch_lock);
	spin_lock_init(&mini->mn_invalidate_lock);
	rcuwait_init(&mini->mn_memslots_update_rcuwait);
	//xa_init(&mini->vcpu_array);

	//mini->max_vcpus = KVM_MAX_VCPUS;

	snprintf(mini->stats_id, sizeof(mini->stats_id), "mini-%d",
		 task_pid_nr(current));

	if (init_srcu_struct(&mini->srcu))
	  return NULL;
		//goto out_err_no_srcu;
	//if (init_srcu_struct(&mini->irq_srcu))
        //return NULL;
		//goto out_err_no_irq_srcu;

	for (i = 0; i < KVM_ADDRESS_SPACE_NUM; i++) {
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
    r = mini_init_mmu_notifier(mini);

    return mini;
}

static void mini_destroy_vm(struct mini *mini)
{
	int i;
    /*
	struct mm_struct *mm = mini->mm;

    mini_info("[mini] destroy_vm %d\n", mm->mm_count);
	mini_destroy_pm_notifier(kvm);
	mini_uevent_notify_change(KVM_EVENT_DESTROY_VM, kvm);
	mini_destroy_vm_debugfs(kvm);
	mini_arch_sync_events(kvm);
	mutex_lock(&mini_lock);
	list_del(&mini->vm_list);
	mutex_unlock(&mini_lock);
    */
#if defined(CONFIG_MMU_NOTIFIER) && defined(MINI_ARCH_WANT_MMU_NOTIFIER)
	//mmu_notifier_unregister(&mini->mmu_notifier, mini->mm);
	/*
	 * At this point, pending calls to invalidate_range_start()
	 * have completed but no more MMU notifiers will run, so
	 * mn_active_invalidate_count may remain unbalanced.
	 * No threads can be waiting in kvm_swap_active_memslots() as the
	 * last reference on KVM has been dropped, but freeing
	 * memslots would deadlock without this manual intervention.
	 */
	mini_info("\t[mini] in #if\n");
	
	WARN_ON(rcuwait_active(&mini->mn_memslots_update_rcuwait));
	mini->mn_active_invalidate_count = 0;
#else
	mini_info("\t[mini] in #else\n");
	mini_flush_shadow_all(mini);
#endif
	//mini_arch_destroy_vm(mini);
	//mini_destroy_devices(kvm);
	for (i = 0; i < KVM_ADDRESS_SPACE_NUM; i++) {
		mini_free_memslots(mini, &mini->__memslots[i][0]);
		mini_free_memslots(mini, &mini->__memslots[i][1]);
	}
	//cleanup_srcu_struct(&kvm->irq_srcu);
	//cleanup_srcu_struct(&mini->srcu);
	mini_arch_free_vm(mini);
	//preempt_notifier_dec();
	//hardware_disable_all();
    //mini_info("\t[mini] before_mmdrop %d\n", mm->mm_count);
	//mmdrop(mm);
    //mini_info("\t[mini] after_mmdrop %d\n", mm->mm_count);
    mini_info("\t[mini] module_put\n");
	//module_put(mini_chardev_ops.owner);
}


static void mini_commit_memory_region(struct mini *mini,
				     struct kvm_memory_slot *old,
				     const struct kvm_memory_slot *new,
				     enum kvm_mr_change change)
{
	int old_flags = old ? old->flags : 0;
	int new_flags = new ? new->flags : 0;
    mini_info("[mini] mini_commit_memory_region\n");
	/*
	 * Update the total number of memslot pages before calling the arch
	 * hook so that architectures can consume the result directly.
	 */
	if (change == KVM_MR_DELETE)
		mini->nr_memslot_pages -= old->npages;
	else if (change == KVM_MR_CREATE)
		mini->nr_memslot_pages += new->npages;

	if ((old_flags ^ new_flags) & KVM_MEM_LOG_DIRTY_PAGES) {
		int change = (new_flags & KVM_MEM_LOG_DIRTY_PAGES) ? 1 : -1;
		atomic_set(&mini->nr_memslots_dirty_logging,
			   atomic_read(&mini->nr_memslots_dirty_logging) + change);
	}

	mini_arch_commit_memory_region(mini, old, new, change);

	switch (change) {
	case KVM_MR_CREATE:
		/* Nothing more to do. */
		break;
	case KVM_MR_DELETE:
		/* Free the old memslot and all its metadata. */
		mini_free_memslot(mini, old);
		break;
	case KVM_MR_MOVE:
	case KVM_MR_FLAGS_ONLY:
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
				     const struct kvm_memory_slot *old,
				     struct kvm_memory_slot *new,
				     enum kvm_mr_change change)
{
	int r;

    mini_info("[mini] mini_prepare_memory_region\n");

	/*
	 * If dirty logging is disabled, nullify the bitmap; the old bitmap
	 * will be freed on "commit".  If logging is enabled in both old and
	 * new, reuse the existing bitmap.  If logging is enabled only in the
	 * new and KVM isn't using a ring buffer, allocate and initialize a
	 * new bitmap.
	 */
	if (change != KVM_MR_DELETE) {
		if (!(new->flags & KVM_MEM_LOG_DIRTY_PAGES))
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
static int kvm_memslots_get_as_id(struct kvm_memory_slot *a,
				  struct kvm_memory_slot *b)
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

static void mini_insert_gfn_node(struct kvm_memslots *slots,
				struct kvm_memory_slot *slot)
{
	struct rb_root *gfn_tree = &slots->gfn_tree;
	struct rb_node **node, *parent;
	int idx = slots->node_idx;

	parent = NULL;
	for (node = &gfn_tree->rb_node; *node; ) {
		struct kvm_memory_slot *tmp;

		tmp = container_of(*node, struct kvm_memory_slot, gfn_node[idx]);
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

static void mini_erase_gfn_node(struct kvm_memslots *slots,
			       struct kvm_memory_slot *slot)
{
	rb_erase(&slot->gfn_node[slots->node_idx], &slots->gfn_tree);
}

static void mini_replace_gfn_node(struct kvm_memslots *slots,
				 struct kvm_memory_slot *old,
				 struct kvm_memory_slot *new)
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
				struct kvm_memory_slot *old,
				struct kvm_memory_slot *new)
{
	int as_id = kvm_memslots_get_as_id(old, new);
	struct kvm_memslots *slots = mini_get_inactive_memslots(mini, as_id);
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
				   struct kvm_memory_slot *old,
				   struct kvm_memory_slot *invalid_slot)
{
	/*
	 * Mark the current slot INVALID.  As with all memslot modifications,
	 * this must be done on an unreachable slot to avoid modifying the
	 * current slot in the active tree.
	 */
	mini_copy_memslot(invalid_slot, old);
	invalid_slot->flags |= KVM_MEMSLOT_INVALID;
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
				 struct kvm_memory_slot *old,
				 struct kvm_memory_slot *new)
{
	int as_id = kvm_memslots_get_as_id(old, new);

    mini_info("[mini] mini_activate_memslot\n");

	mini_swap_active_memslots(mini, as_id);

	/* Propagate the new memslot to the now inactive memslots. */
	mini_replace_memslot(mini, old, new);
}


static void mini_update_flags_memslot(struct mini *mini,
				     struct kvm_memory_slot *old,
				     struct kvm_memory_slot *new)
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
			       struct kvm_memory_slot *new)
{
	/* Add the new memslot to the inactive set and activate. */
    mini_info("[mini] mini_create_memslot\n");
	mini_replace_memslot(mini, NULL, new);
	mini_activate_memslot(mini, NULL, new);
}

static void mini_delete_memslot(struct mini *mini,
			       struct kvm_memory_slot *old,
			       struct kvm_memory_slot *invalid_slot)
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
			     struct kvm_memory_slot *old,
			     struct kvm_memory_slot *new,
			     struct kvm_memory_slot *invalid_slot)
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
			   struct kvm_memory_slot *old,
			   struct kvm_memory_slot *new,
			   enum kvm_mr_change change)
{
	struct kvm_memory_slot *invalid_slot;
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
	 * delete/move and committing the changes in arch code where KVM or a
	 * guest could access a non-existent memslot.
	 *
	 * Modifications are done on a temporary, unreachable slot.  The old
	 * slot needs to be preserved in case a later step fails and the
	 * invalidation needs to be reverted.
	 */
	if (change == KVM_MR_DELETE || change == KVM_MR_MOVE) {
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
		if (change == KVM_MR_DELETE || change == KVM_MR_MOVE) {
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
	if (change == KVM_MR_CREATE)
		mini_create_memslot(mini, new);
	else if (change == KVM_MR_DELETE)
		mini_delete_memslot(mini, old, invalid_slot);
	else if (change == KVM_MR_MOVE)
		mini_move_memslot(mini, old, new, invalid_slot);
	else if (change == KVM_MR_FLAGS_ONLY)
		mini_update_flags_memslot(mini, old, new);
	else
		BUG();

	/* Free the temporary INVALID slot used for DELETE and MOVE. */
	if (change == KVM_MR_DELETE || change == KVM_MR_MOVE)
		kfree(invalid_slot);

	/*
	 * No need to refresh new->arch, changes after dropping slots_arch_lock
	 * will directly hit the final, active memslot.  Architectures are
	 * responsible for knowing that new->arch may be stale.
	 */
	mini_commit_memory_region(mini, old, new, change);

	return 0;
}

static bool mini_check_memslot_overlap(struct kvm_memslots *slots, int id,
				      gfn_t start, gfn_t end)
{
	struct kvm_memslot_iter iter;

	kvm_for_each_memslot_in_gfn_range(&iter, slots, start, end) {
		if (iter.slot->id != id)
			return true;
	}

	return false;
}

static bool mini_is_ad_tracked_page(struct page *page)
{
    return !PageReserved(page);
}

static void mini_set_page_dirty(struct page *page)
{
    if(mini_is_ad_tracked_page(page))
        SetPageDirty(page);
}

static void mini_set_page_accessed(struct page *page)
{
    if(mini_is_ad_tracked_page(page))
        mark_page_accessed(page);
}

void mini_release_page_clean(struct page *page)
{
    //mini_info("[mini] before mini_release_page_clean ref : %d\n", page->_refcount);
    WARN_ON(is_error_page(page));

    mini_set_page_accessed(page);
    put_page(page);
    //mini_info("[mini] after mini_release_page_clean ref : %d\n", page->_refcount);
}
EXPORT_SYMBOL_GPL(mini_release_page_clean);

void mini_release_pfn_clean(kvm_pfn_t pfn)
{
    struct page *page;
    //mini_info("[mini] release_pfn_clean 0x%lx\n", pfn);

    if (is_error_noslot_pfn(pfn)){
        mini_info("\t[mini] pfn slot error\n");
        return;
    }

    page = mini_pfn_to_refcounted_page(pfn);
    if (!page) {
      //mini_info("\t[mini] page not founded\n");
        return;
    }

    mini_release_page_clean(page);
}
EXPORT_SYMBOL_GPL(mini_release_pfn_clean);

void mini_release_page_dirty(struct page *page)
{
    WARN_ON(is_error_page(page));

    mini_set_page_dirty(page);
    mini_release_page_clean(page);
}
EXPORT_SYMBOL_GPL(mini_release_page_dirty);

void mini_release_pfn_dirty(kvm_pfn_t pfn)
{
    struct page *page;

    if(is_error_noslot_pfn(pfn))
        return;

    page = mini_pfn_to_refcounted_page(pfn);
    if(!page)
        return;

    mini_release_page_dirty(page);
}
EXPORT_SYMBOL_GPL(mini_release_pfn_dirty);

void mini_set_pfn_accessed(kvm_pfn_t pfn)
{
    if (WARN_ON(is_error_noslot_pfn(pfn)))
        return ;

    if(pfn_valid(pfn))
        mini_set_page_accessed(pfn_to_page(pfn));
}
EXPORT_SYMBOL_GPL(mini_set_pfn_accessed);


/*
 * Allocate some memory and give it an address in the guest physical address
 * space.
 *
 * Discontiguous memory is allowed, mostly for framebuffers.
 *
 * Must be called holding mini->slots_lock for write.
 */
int __mini_set_memory_region(struct mini *mini,
			    const struct kvm_userspace_memory_region *mem)
{
  struct kvm_memory_slot *old, *new;
  struct kvm_memslots *slots;
  enum kvm_mr_change change;
  unsigned long npages;
  gfn_t base_gfn;
  int as_id, id;
  int r;
	
  mini_info("[mini] __mini_set_memory_region\n");

  mini_info("\t[mini] mem->slot : 0x%x\n", mem->slot);
  mini_info("\t[mini] mem->flags : 0x%x\n", mem->flags);
  mini_info("\t[mini] mem->guest_phys_addr: 0x%lx\n", mem->guest_phys_addr);
  mini_info("\t[mini] mem->memory_size : 0x%lx\n", mem->memory_size);
  mini_info("\t[mini] mem->userspace_addr : 0x%lx\n", mem->userspace_addr);
  
  r = check_memory_region_flags(mem);
  if (r)
    return r;
  
  as_id = mem->slot >> 16;
  id = (u16)mem->slot;
  
  //mini_info("\t[mini] mem->memory_size : %ld\n", mem->memory_size);
  //mini_info("\t[mini] PAGE_SIZE : %ld\n", PAGE_SIZE);
  //mini_info("\t[mini] (unsigned long) mem->memory_size : %ld\n", (unsigned long)mem->memory_size);
  //mini_info("\t[mini] result : %d, %d\n", mem->memory_size & (PAGE_SIZE -1), mem->memory_size != (unsigned long)mem->memory_size);
  
  /* General sanity checks */
  mini_info("[mini] __mini_set_memory_region_before_sanity\n");

  if ((mem->memory_size & (PAGE_SIZE - 1)) ||
      (mem->memory_size != (unsigned long)mem->memory_size))
    return -EINVAL;
  mini_info("\t[mini] memory_size\n");
  if (mem->guest_phys_addr & (PAGE_SIZE - 1))
    return -EINVAL;
  mini_info("\t[mini] phys_addr\n");

  /* We can read the guest memory with __xxx_user() later on. */
  /*
    if ((mem->userspace_addr & (PAGE_SIZE - 1)) ||
    (mem->userspace_addr != untagged_addr(mem->userspace_addr)) ||
    !access_ok((void __user *)(unsigned long)mem->userspace_addr,
    mem->memory_size))
    return -EINVAL;
  mini_info("\t[mini] userspace_addr\n");
  */

  if (as_id >= KVM_ADDRESS_SPACE_NUM || id >= KVM_MEM_SLOTS_NUM)
    return -EINVAL;
  mini_info("\t[mini] as_id\n");
  if (mem->guest_phys_addr + mem->memory_size < mem->guest_phys_addr)
    return -EINVAL;
  mini_info("\t[mini] guest_phys_addr + memory_size\n");
  if ((mem->memory_size >> PAGE_SHIFT) > KVM_MEM_MAX_NR_PAGES)
    return -EINVAL;
  mini_info("\t[mini] PAGE_SHIFT\n");
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
  mini_info("old : 0x%lx\n", (__u64) old);
  
  mini_info("size : %d\n", mem->memory_size);
  if (!mem->memory_size) {
    if (!old || !old->npages)
      return -EINVAL;
    if (WARN_ON_ONCE(mini->nr_memslot_pages < old->npages))
      return -EIO;
    return mini_set_memslot(mini, old, NULL, KVM_MR_DELETE);
  }
  mini_info("\t[mini] size checked\n");

  base_gfn = (mem->guest_phys_addr >> PAGE_SHIFT);
  npages = (mem->memory_size >> PAGE_SHIFT);

  if (!old || !old->npages) {
    mini_info("\t[mini] if(old)\n");
    change = KVM_MR_CREATE;

    /*
     * To simplify KVM internals, the total number of pages across
     * all memslots must fit in an unsigned long.
     */
    if ((mini->nr_memslot_pages + npages) < mini->nr_memslot_pages)
      return -EINVAL;
  } else { /* Modify an existing slot. */
    mini_info("\t[mini] else\n");
    if ((mem->userspace_addr != old->userspace_addr) ||
	(npages != old->npages) ||
	((mem->flags ^ old->flags) & KVM_MEM_READONLY))
      return -EINVAL;

    if (base_gfn != old->base_gfn)
      change = KVM_MR_MOVE;
    else if (mem->flags != old->flags)
      change = KVM_MR_FLAGS_ONLY;
    else /* Nothing to change. */
      return 0;
  }
  mini_info("\t[mini] page checked\n");

  if ((change == KVM_MR_CREATE || change == KVM_MR_MOVE) &&
      mini_check_memslot_overlap(slots, id, base_gfn, base_gfn + npages))
    return -EEXIST;
  mini_info("\t[mini] change checked\n");

  /* Allocate a slot that will persist in the memslot. */
  new = kzalloc(sizeof(*new), GFP_KERNEL_ACCOUNT);
  if (!new)
    return -ENOMEM;
  mini_info("\t[mini] allocated\n");

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
			  const struct kvm_userspace_memory_region *mem)
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
	return (pgoff >= KVM_DIRTY_LOG_PAGE_OFFSET) &&
	    (pgoff < KVM_DIRTY_LOG_PAGE_OFFSET +
	     mini->dirty_ring_size / PAGE_SIZE);
#else
	return false;
#endif
}

static int mini_vm_ioctl_set_memory_region(struct mini *mini,
					  struct kvm_userspace_memory_region *mem)
{
	if ((u16)mem->slot >= KVM_USER_MEM_SLOTS)
		return -EINVAL;

	return mini_set_memory_region(mini, mem);
}

static long mini_vm_ioctl(struct file *flip,
            unsigned int ioctl, unsigned long arg)
{
    struct mini *mini = flip->private_data;
	void __user *argp = (void __user *)arg;
    int r;

    mini_info("[mini] mini_vm_ioctl\n");

    switch(ioctl) {
    }
    return r;

out:
    return r;
}

static bool memslot_is_readonly(const struct kvm_memory_slot *slot)
{
	return slot->flags & KVM_MEM_READONLY;
}

static unsigned long __gfn_to_hva_many(const struct kvm_memory_slot *slot, gfn_t gfn,
				       gfn_t *nr_pages, bool write)
{
	if (!slot || slot->flags & KVM_MEMSLOT_INVALID)
		return KVM_HVA_ERR_BAD;

	if (memslot_is_readonly(slot) && write)
		return KVM_HVA_ERR_RO_BAD;

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

static int mini_try_get_pfn(kvm_pfn_t pfn)
{
	struct page *page = mini_pfn_to_refcounted_page(pfn);

	if (!page)
		return 1;

	return get_page_unless_zero(page);
}

unsigned long gfn_to_hva_memslot_prot(struct kvm_memory_slot *slot,
				      gfn_t gfn, bool *writable)
{
	unsigned long hva = __gfn_to_hva_many(slot, gfn, NULL, false);

	if (!kvm_is_error_hva(hva) && writable)
		*writable = !memslot_is_readonly(slot);

	return hva;
}

/*
 * The fast path to get the writable pfn which will be stored in @pfn,
 * true indicates success, otherwise false is returned.  It's also the
 * only part that runs if we can in atomic context.
 */
static bool hva_to_pfn_fast(unsigned long addr, bool write_fault,
			    bool *writable, kvm_pfn_t *pfn)
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
			   bool interruptible, bool *writable, kvm_pfn_t *pfn)
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
			       bool *writable, kvm_pfn_t *p_pfn)
{
	kvm_pfn_t pfn;
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
		pfn = KVM_PFN_ERR_RO_FAULT;
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
kvm_pfn_t hva_to_pfn(unsigned long addr, bool atomic, bool interruptible,
		     bool *async, bool write_fault, bool *writable)
{
	struct vm_area_struct *vma;
	kvm_pfn_t pfn;
	int npages, r;

    mini_info("[mini] hva_to_pfn\n");

	/* we can do it either atomically or asynchronously, not both */
	BUG_ON(atomic && async);

	if (hva_to_pfn_fast(addr, write_fault, writable, &pfn))
		return pfn;

	if (atomic)
		return KVM_PFN_ERR_FAULT;

	npages = hva_to_pfn_slow(addr, async, write_fault, interruptible,
				 writable, &pfn);
	if (npages == 1)
		return pfn;
	if (npages == -EINTR)
		return KVM_PFN_ERR_SIGPENDING;

	mmap_read_lock(current->mm);
	if (npages == -EHWPOISON ||
	      (!async && check_user_page_hwpoison(addr))) {
		pfn = KVM_PFN_ERR_HWPOISON;
		goto exit;
	}

retry:
	vma = vma_lookup(current->mm, addr);

	if (vma == NULL)
		pfn = KVM_PFN_ERR_FAULT;
	else if (vma->vm_flags & (VM_IO | VM_PFNMAP)) {
		r = hva_to_pfn_remapped(vma, addr, write_fault, writable, &pfn);
		if (r == -EAGAIN)
			goto retry;
		if (r < 0)
			pfn = KVM_PFN_ERR_FAULT;
	} else {
		if (async && vma_is_valid(vma, write_fault))
			*async = true;
		pfn = KVM_PFN_ERR_FAULT;
	}
exit:
	mmap_read_unlock(current->mm);
	return pfn;
}

kvm_pfn_t mini__gfn_to_pfn_memslot(const struct kvm_memory_slot *slot, gfn_t gfn,
			       bool atomic, bool interruptible, bool *async,
			       bool write_fault, bool *writable, hva_t *hva)
{
	unsigned long addr = __gfn_to_hva_many(slot, gfn, NULL, write_fault);

    mini_info("[mini] mini__gfn_to_pfn_memslot 0x%lx, 0x%lx\n", hva, addr);

	if (hva)
		*hva = addr;

	if (addr == KVM_HVA_ERR_RO_BAD) {
		if (writable)
			*writable = false;
		return KVM_PFN_ERR_RO_FAULT;
	}

	if (kvm_is_error_hva(addr)) {
		if (writable)
			*writable = false;
		return KVM_PFN_NOSLOT;
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

kvm_pfn_t mini_gfn_to_pfn_prot(struct mini *mini, gfn_t gfn, bool write_fault,
		      bool *writable)
{
	return mini__gfn_to_pfn_memslot(mini_gfn_to_memslot(mini, gfn), gfn, false, false,
				    NULL, write_fault, writable, NULL);
}
EXPORT_SYMBOL_GPL(mini_gfn_to_pfn_prot);

struct kvm_memory_slot *mini_gfn_to_memslot(struct mini *mini, gfn_t gfn)
{
	return __gfn_to_memslot(mini_memslots(mini), gfn);
}
EXPORT_SYMBOL_GPL(mini_gfn_to_memslot);

static const struct file_operations mini_vm_fops = {
    .unlocked_ioctl = mini_vm_ioctl,
	.llseek		= noop_llseek,
};

 
// dev ioctl static functions

// Create VM
static struct mini *mini_dev_ioctl_create_vm(unsigned long type)
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
    mini->vid = type;

    file = anon_inode_getfile("mini-vm", &mini_vm_fops, mini, O_RDWR);
    if(IS_ERR(file)) {
        r = PTR_ERR(file);
    }

    fd_install(fd, file);
    //return fd;
    return mini;

}

// Map g-stage page
static int verse_map_gstage_pages (struct mini *mini, struct kvm_userspace_memory_region *map_info)
{
  int r = mini_vm_ioctl_set_memory_region(mini, map_info);
  if(r != 0) {
    mini_info("Failed to set memory region\n");
    return -1;
  }

  gpa_t gpa = map_info->guest_phys_addr;
  gfn_t gfn = gpa >> (PAGE_SHIFT);
  struct kvm_memory_slot *memslot = mini_gfn_to_memslot(mini, gfn);
  bool writable = true;
  int count = 0;

  // Create GPA 2 HPA mapping 
  while(count < memslot->npages) { 
    //mini_info("prog : %d / %d\n", count+1, memslot->npages);
    /*
      kvm_pfn_t hfn = mini_gfn_to_pfn_prot(mini, gfn, true, &writable);
      mini_info("get hfn %lx\n", hfn);
      phys_addr_t hpa = hfn << PAGE_SHIFT;
      mini_info("get hpa %lx\n", hpa);
    */
    gfn = gpa >> (PAGE_SHIFT);
    unsigned long hva = gfn_to_hva_memslot_prot(memslot, gfn, &writable);
    //mini_info("get hva %lx\n", hva);

    /*
      mini_info("\t[mini] gpa : 0x%x, gfn : 0x%x, hva : 0x%lx, hfn : 0x%x, hpa : 0x%x\n",
      gpa, gfn, hva, hfn, hpa); 
      mini_info("\t[mini] pages %d\tuser_addr 0x%lx\t id %d\n", 
      memslot->npages, memslot->userspace_addr, memslot->id); 
      mini_info("\t[mini] task_size %d\n", mini->mm->task_size); 
      mini_info("\t[mini] pagetables_bytes %d\n", mini->mm->pgtables_bytes); 
      mini_info("\t[mini] total_vm %d\n", mini->mm->total_vm); 
    */ 
    r = mini_riscv_gstage_map(mini, memslot, gpa, hva, true); 
    //mini_riscv_gstage_map(vcpu, memslot, gpa, hva, true); 
    if(r) { 
      mini_info("map failed\n"); 
      return r; 
    } 
    //mini_info("map succedded\n"); 
    //mini_release_pfn_clean(hfn); 
    gpa += PAGE_SIZE; 
    count ++; 
  } // while end 
    //mini_info("\t[mini] map_count %d\n", mini->mm->map_count); 
    
  return r;
}

// Unmap g-stage page
static int verse_unmap_gstage_pages(void)
{
  mini_info("veres_unmap_gstage_pages\n");
  return 0;
}

// Map g-stage pages to host virtaul address for JIT code excution
static int verse_map_executable_pages(void)
{
  mini_info("verse_map_executable_pages\n");
  return 0;
}

// Unmap g-stage pages from host virtual address
static int verse_unmap_executable_pages(void)
{
  mini_info("verse_unmap_executable_pages\n");
  return 0;
}

static long mini_dev_ioctl(struct file *flip, 
            unsigned int ioctl, unsigned long arg)
{
    long r = -EINVAL;
    mini_info("mini_dev_ioctl, %x, %u\n", ioctl, arg);

    static struct mini *mini_array[1024];
    static int current_mini = -1;
    struct mini *mini = NULL;

    int count = 0;

    switch(ioctl) {
    case MINI_CREATE_VM: 
      mini_info("[mini] verse_create\n");
      //r = mini_dev_ioctl_create_vm(arg);
      if(mini_array[arg] != NULL) {
	mini_info("%d is already used\n");
	r = -EFAULT;
      }
      else {
	mini_array[arg] = mini_dev_ioctl_create_vm(arg);
	r = 0;
      }
      break;
    case MINI_DEST_VM:
      mini_info("[mini] verse_dest\n");
      
      // Not created
      if(mini_array[arg] == NULL) {
	  mini_info("[mini] %d th verse is not created\n", arg);
	  r = -EFAULT;
      }
      //kfree(mini_array[arg]->mini_kva);
	
      if(mini_array[arg]->mini_kva != NULL) {
	mini_info("[mini] free vm pages\n");
	free_pages(mini_array[arg]->mini_kva, get_order(mini_array[arg]->memory_size));
      }
      mini_info("[mini] free stack pages\n");
      free_pages(mini_array[arg]->mini_stack_base_kva, 10);

      //mini_destroy_vm(mini_array[arg]);
      mini_array[arg] = NULL;
      r = 0;
      break;
    case VERSE_MMAP: {
        mini_info("VERSE_MMAP\n");

        if(current_mini < 0)  {
            mini_info("Need enter first\n");
            return -1;
        }

	struct kvm_userspace_memory_region mini_userspace_mem;

        void __user *argp = (void __user *)arg;

        mini = mini_array[current_mini];
        if(mini == NULL) {
            mini_err("Can't find %dth\n", current_mini);
            return -EFAULT;
        }

	r = -EFAULT;
	if (copy_from_user(&mini_userspace_mem, argp,
			   sizeof(mini_userspace_mem))) {
	  return r;
        }

        ///////////////////////////////////////////////////////////////////////////
        // Requested Memory Allocation
        ///////////////////////////////////////////////////////////////////////////
        
        if((mini_userspace_mem.memory_size & (PAGE_SIZE - 1)) != 0) {
            mini_info("Alignment 0x%x to 0x%x\n", mini_userspace_mem.memory_size, (mini_userspace_mem.memory_size + PAGE_SIZE -1) & ~(PAGE_SIZE-1));
            mini_userspace_mem.memory_size = (mini_userspace_mem.memory_size + PAGE_SIZE -1) & ~(PAGE_SIZE-1);
        }

        unsigned long new_page = __get_free_pages(GFP_KERNEL, get_order(mini_userspace_mem.memory_size));
        mini_info("page : 0x%lx\n", new_page);
        mini_userspace_mem.userspace_addr = new_page;


        //mini_userspace_mem.userspace_addr = (unsigned long)kmalloc(mini_userspace_mem.memory_size, GFP_KERNEL);
        mini->mini_kva = mini_userspace_mem.userspace_addr;
        mini->memory_size = mini_userspace_mem.memory_size;
        mini->base_gpa = mini_userspace_mem.guest_phys_addr;
        mini->mmu_page_cache.gfp_zero = __GFP_ZERO;

        
        // Call mapping function
        verse_map_gstage_pages(mini, &mini_userspace_mem);

	r = mini->base_gpa;

	mini_info("GPA : 0x%lx\n", r);
	
        ///////////////////////////////////////////////////////////////////////////
        // Stack Allocation
        ///////////////////////////////////////////////////////////////////////////
        mini_info("[mini] MINI_STACK_ALLOC\n");

	if (mini->mini_stack_base_kva != NULL) {
	  mini_info("[mini] stack already allocated\n");
	  return 0;
	}
	unsigned long stack_start = current->mm->start_stack;
	
	struct kvm_userspace_memory_region mini_vm_stack = {
            1,
            0,
            (stack_start & 0xFFFFFFF000) - (PAGE_SIZE * 512),
            PAGE_SIZE * 1024,
            0 
        };

        mini_info("[mini] START_STACK = 0x%016lx,\tGPA_START = 0x%016lx\n", stack_start, mini_vm_stack.guest_phys_addr);

        unsigned long stack_page = __get_free_pages(GFP_KERNEL, get_order(mini_vm_stack.memory_size));
        mini_vm_stack.userspace_addr = stack_page;
        mini->mini_stack_base_kva = stack_page;

        verse_map_gstage_pages(mini, &mini_vm_stack);
	break;
    }
    case MINI_FREE: {
        mini_info("VERSE_MUNMAP\n");
	verse_unmap_gstage_pages();

        r = -EFAULT;

        if(current_mini < 0) {
            mini_info("Need to enter\n");
            return r;
        }

        mini = mini_array[current_mini];

        gpa_t gpa = mini->base_gpa;
        gfn_t gfn = gpa >> (PAGE_SHIFT);
        struct kvm_memory_slot *memslot = mini_gfn_to_memslot(mini, gfn);
        mini = mini_array[current_mini];
        unsigned long hva = mini->mini_kva;

        mini_info("\tVariables\n");

	// Modify the PTEs and free the pages
        /*
        while(count < memslot->npages) { 
            mini_info("prog : %d / %d\n", count+1, memslot->npages);
            mini_info("get hva %lx\n", hva);

            struct page *p = virt_to_page(hva);

            mini_info("ref count = %d\n", page_ref_count(p));
            page_ref_dec(p);
            mini_info("ref count = %d\n", page_ref_count(p));

            hva += PAGE_SIZE;

            count ++;

        } // End of while
        */

        mini_riscv_gstage_iounmap(mini, gpa, mini->memory_size);

	free_pages(hva, 0);
	mini->mini_kva = 0;

        r = 0;

        break;
    }
    case MINI_ENTER: {
        current_mini = arg;

        if(mini_array[current_mini] == NULL) {
            mini_info("[mini] Can't find %dth mini\n", current_mini);
            current_mini = -1;
            return -1;
        }

        mini = mini_array[current_mini];

        mini_arch_enter(mini);
        csr_write(CSR_HSTATUS, csr_read(CSR_HSTATUS) | HSTATUS_HU);
        mini_info("MINI_ENTER : 0x%x\n", csr_read(CSR_HSTATUS));
        break;
    }
    case MINI_EXIT: {
      int isFast = arg;

      if(current_mini < 0) {
	mini_info("[mini] not in enter\n");
	return -1;
      }
      mini = mini_array[current_mini];

      csr_write(CSR_HSTATUS, csr_read(CSR_HSTATUS) & !HSTATUS_HU);
      mini_info("MINI_EXIT 0x%x\n", csr_read(CSR_HSTATUS));
      
      if (isFast == 0) {
	mini_arch_exit(mini);
      }
      
      current_mini = -1;
      
      break;
    }
    case VERSE_MAP_EXECUTABLE: {
      struct kvm_userspace_memory_region mini_userspace_mem;
      struct vm_area_struct *vma;
      void __user *argp = (void __user *)arg;

      mini_info("VERSE_MAP_EXECUTABLE\n");

      if(current_mini < 0) {
	mini_info("[mini] Need enter first\n");
	return -1;
      }

      mini = mini_array[current_mini];
      
      if(mini == NULL) {
	mini_err("Can't find %dth\n", current_mini);
	return -EFAULT;
      }

      r = -EFAULT;
      if (copy_from_user(&mini_userspace_mem, argp,
			 sizeof(mini_userspace_mem))) {
	return r;
      }
      mini_info("[mini] copy_from_user\n");

      vma = vma_lookup(current->mm, mini_userspace_mem.userspace_addr);
      mini_info("[mini] vma_lookup 0x%lx to 0x%lx\n", vma->vm_start, vma->vm_end);
      // gpa_to_gfn, gfn_to_hva
      mini_info("[mini] pfn : 0x%x\n", virt_to_pfn(mini->mini_kva));
      remap_pfn_range(vma, mini_userspace_mem.userspace_addr, virt_to_pfn(mini->mini_kva), mini_userspace_mem.memory_size, vma->vm_page_prot);
      //verse_map_executable_pages();
      
      break;
    }
    case VERSE_UNMAP_EXECUTABLE: {
      mini_info("VERSE_UNMAP_EXECUTABLE\n");
      break;
    }
    case MINI_GET_VCPU_MMAP_SIZE:
      if (arg)
	return r;
      r = PAGE_SIZE;     /* struct kvm_run */
#ifdef CONFIG_KVM_MMIO
      r += PAGE_SIZE;    /* coalesced mmio ring page */
#endif
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

static long mini_vcpu_ioctl(struct file *filp,
			   unsigned int ioctl, unsigned long arg)
{
    struct mini_vcpu *vcpu = filp->private_data;
    void __user *argv = (void __user *)arg;

    struct mini *mini = vcpu->mini;
    gpa_t gpa = mini->base_gpa;
    gfn_t gfn = gpa >> (PAGE_SHIFT);
    struct kvm_memory_slot *memslot = mini_gfn_to_memslot(mini, gfn);
    int count = 0;

    int r = 0;

    mini_info("[mini] mini_vcpu_ioctl\n");


	if (vcpu->mini->mm != current->mm || vcpu->mini->vm_dead)
		return -EIO;
    mini_info("[mini] mm\n");

	if (unlikely(_IOC_TYPE(ioctl) != MINIIO))
		return -EINVAL;
    mini_info("[mini] KVMIO\n");

	switch (ioctl) {
    }

    return r;
}

int mini_init(unsigned vcpu_size, unsigned vcpu_align, struct module *module)
{

    mini_info("[mini] mini_init %x %x\n", vcpu_size, vcpu_align);

    major = register_chrdev(0, DEVICE_NAME, &mini_chardev_ops);
    if(major < 0) {
        mini_info("Registering char device failed with %d\n", major);
        return major;
    }

    mini_info("Assigned major number : %d\n", major);

    cls = class_create(DEVICE_NAME);
    device_create(cls, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);

    unsigned long long scounteren = csr_read(CSR_SCOUNTEREN);
    mini_info("scounteren: 0x%x\n", scounteren);
    csr_write(CSR_SCOUNTEREN, 0x7f);
    scounteren = csr_read(CSR_SCOUNTEREN);
    mini_info("scounteren: 0x%x\n", scounteren);

    return 0;
}
EXPORT_SYMBOL_GPL(mini_init);
