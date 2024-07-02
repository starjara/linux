#ifndef __MINI_HOST_H
#define __MINI_HOST_H

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/rbtree.h>
#include <linux/mmu_notifier.h>
#include <linux/hashtable.h>
#include <linux/interval_tree.h>
#include <linux/nospec.h>
#include <linux/rcuwait.h>
#include <linux/xarray.h>

#include <linux/mini.h>
#include <linux/kvm.h>

//#include <linux/mini_types.h>
#include <linux/kvm_types.h>

#include <asm/mini_host.h>
#include <linux/mini_dirty_ring.h>

#include <linux/kvm_host.h>

#define mini_err(fmt, ...) \
    pr_err("mini [%i]: " fmt, task_pid_nr(current), ## __VA_ARGS__)
#define mini_info(fmt, ...) \
    pr_info("mini [%i]: " fmt, task_pid_nr(current), ## __VA_ARGS__)

static struct mm_struct *module_mm;

bool mini_make_vcpus_request_mask(struct mini *mini, unsigned int req,
				 unsigned long *vcpu_bitmap);
bool mini_make_all_cpus_request(struct mini *mini, unsigned int req);
bool mini_make_all_cpus_request_except(struct mini *mini, unsigned int req,
				      struct mini_vcpu *except);
bool mini_make_cpus_request_mask(struct mini *mini, unsigned int req,
				unsigned long *vcpu_bitmap);

struct mini_vcpu {
	struct mini *mini;
#ifdef CONFIG_PREEMPT_NOTIFIERS
	struct preempt_notifier preempt_notifier;
#endif //CONFIG_PREEMPT_NOTIFIERS
	int cpu;
	int vcpu_id; /* id given by userspace at creation */
	int vcpu_idx; /* index into mini->vcpu_array */
	int ____srcu_idx; /* Don't use this directly.  You've been warned. */
#ifdef CONFIG_PROVE_RCU
	int srcu_depth;
#endif //CONFIG_PROVE_RCU
	int mode;
	u64 requests;
	unsigned long guest_debug;

	struct mutex mutex;
	struct mini_run *run;

#ifndef __KVM_HAVE_ARCH_WQP
	struct rcuwait wait;
#endif //__KVM_HVAE_ARCH_WQP
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
	struct mini_mmio_fragment mmio_fragments[KVM_MAX_MMIO_FRAGMENTS];
#endif

#ifdef CONFIG_KVM_ASYNC_PF
	struct {
		u32 queued;
		struct list_head queue;
		struct list_head done;
		spinlock_t lock;
	} async_pf;
#endif
*/

#ifdef CONFIG_HAVE_KVM_CPU_RELAX_INTERCEPT
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
#endif // CONFIG_HAVE_KVM_CPU_RELAX_INTERCEPT
	bool preempted;
	bool ready;
	struct mini_vcpu_arch arch;
	struct kvm_vcpu_stat stat;
	char stats_id[KVM_STATS_NAME_SIZE];
	struct mini_dirty_ring dirty_ring;

	/*
	 * The most recently used memslot by this vCPU and the slots generation
	 * for which it is valid.
	 * No wraparound protection is needed since generations won't overflow in
	 * thousands of years, even assuming 1M memslot operations per second.
	 */
	struct kvm_memory_slot *last_used_slot;
	u64 last_used_slot_gen;
};

static inline unsigned long mini_dirty_bitmap_bytes(struct kvm_memory_slot *memslot)
{
	return ALIGN(memslot->npages, BITS_PER_LONG) / 8;
}

struct mini {
#ifdef KVM_HAVE_MMU_RWLOCK
	rwlock_t mmu_lock;
#else
	spinlock_t mmu_lock;
#endif /* KVM_HAVE_MMU_RWLOCK */

    /// Custom variables
    gpa_t base_gpa; // Base address of the GPA
    int vid;        // User declared VID
	struct kvm_mmu_memory_cache mmu_page_cache; // page cache
    unsigned long mini_kva;
    unsigned long mini_stack_base_kva;
    __u64 memory_size;    
    // End of custom variables

  struct mutex slots_lock;
  struct mutex slots_arch_lock;

  struct mm_struct *mm; /* userspace tied to this vm */

  unsigned long nr_memslot_pages;

  struct kvm_vm_stat stat;
  struct mini_arch arch;
  refcount_t users_count;

  struct kvm_memslots __memslots[KVM_ADDRESS_SPACE_NUM][2];
  struct kvm_memslots __rcu *memslots[KVM_ADDRESS_SPACE_NUM];

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
  
#if defined(CONFIG_MMU_NOTIFIER) && defined(KVM_ARCH_WANT_MMU_NOTIFIER)
  struct mmu_notifier mmu_notifier;
  unsigned long mmu_invalidate_seq;
  long mmu_invalidate_in_progress;
  unsigned long mmu_invalidate_range_start;
  unsigned long mmu_invalidate_range_end;
#endif //define(CONFIG_MMU_NOTIFIER)

  bool vm_dead;

  char stats_id[KVM_STATS_NAME_SIZE];

};

#ifndef __MINI_HAVE_ARCH_VM_ALLOC
static inline struct mini *mini_arch_alloc_vm(void)
{
    return kzalloc(sizeof(struct mini), GFP_KERNEL_ACCOUNT);
}
#endif //__MINI_HVAE_ARCH_VM_ALLOC

static inline void __mini_arch_free_vm(struct mini *mini)
{
	kvfree(mini);
}

#ifndef __MINI_HAVE_ARCH_VM_FREE
static inline void mini_arch_free_vm(struct mini *mini)
{
	__mini_arch_free_vm(mini);
}
#endif

static inline struct kvm_memslots *__mini_memslots(struct mini *mini, int as_id)
{
  //mini_info("[mini] __kvm_memslots\n");
  as_id = array_index_nospec(as_id, KVM_ADDRESS_SPACE_NUM);

  //mini_info("[mini] __kvm_memslots as_id : 0x%x\n", as_id);
  //mini_info("[mini] __kvm_memslots mini->memslots[as_id] : 0x%x\n", mini->memslots[as_id]);

  //mini_info("[mini] __kvm_memslots: 0x%x\n", 
  //         srcu_dereference_check(mini->memslots[as_id], &mini->srcu,
  //			lockdep_is_held(&mini->slots_lock) ||
  //			!refcount_read(&mini->users_count)));

  return srcu_dereference_check(mini->memslots[as_id], &mini->srcu,
				lockdep_is_held(&mini->slots_lock) ||
				!refcount_read(&mini->users_count));
}

static inline struct kvm_memslots *mini_memslots(struct mini *mini)
{
	return __mini_memslots(mini, 0);
}

static inline
struct kvm_memory_slot *mini_id_to_memslot(struct kvm_memslots *slots, int id)
{

  //mini_info("[mini] id_to_memslot\n");
  struct kvm_memory_slot *slot;
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


void mini_destroy_vcpus(struct mini *mini);

static inline void __mini_make_request(int req, struct mini_vcpu *vcpu)
{
	/*
	 * Ensure the rest of the request is published to mini_check_request's
	 * caller.  Paired with the smp_mb__after_atomic in mini_check_request.
	 */
	smp_wmb();
	set_bit(req & KVM_REQUEST_MASK, (void *)&vcpu->requests);
}

static inline bool mini_dirty_log_manual_protect_and_init_set(struct mini *mini)
{
	return !!(mini->manual_dirty_log_protect & KVM_DIRTY_LOG_INITIALLY_SET);
}

int mini_set_memory_region(struct mini *mini,
			  const struct kvm_userspace_memory_region *mem);
int __mini_set_memory_region(struct mini *mini,
			    const struct kvm_userspace_memory_region *mem);
int mini_init(unsigned vcpu_size, unsigned vcpu_align, struct module *module);
void mini_exit(void);

int mini_arch_init_vm(struct mini *mini, unsigned long type);
void mini_arch_destroy_vm(struct mini *mini);

int mini_arch_enter(struct mini *mini);
int mini_arch_exit(struct mini *mini);

#ifndef __KVM_HAVE_ARCH_FLUSH_REMOTE_TLB
static inline int mini_arch_flush_remote_tlb(struct mini *mini)
{
	return -ENOTSUPP;
}
#endif //__KVM_HAVE_ARCH_FLUSH_REMOTE_TLB

bool kvm_is_zone_device_page(struct page *page);

void mini_arch_free_memslot(struct mini *mini, struct kvm_memory_slot *slot);
void mini_arch_memslots_updated(struct mini *mini, u64 gen);
int mini_arch_prepare_memory_region(struct mini *mini,
				const struct kvm_memory_slot *old,
				struct kvm_memory_slot *new,
				enum kvm_mr_change change);
void mini_arch_commit_memory_region(struct mini *mini,
				struct kvm_memory_slot *old,
				const struct kvm_memory_slot *new,
				enum kvm_mr_change change);
/* flush all memory translations */
void mini_arch_flush_shadow_all(struct mini *mini);
/* flush memory translations pointing to 'slot' */
void mini_arch_flush_shadow_memslot(struct mini *mini,
				   struct kvm_memory_slot *slot);
void mini_arch_guest_memory_reclaimed(struct mini *mini);

struct kvm_memory_slot *mini_gfn_to_memslot(struct mini *mini, gfn_t gfn);
kvm_pfn_t mini_gfn_to_pfn_prot(struct mini *mini, gfn_t gfn, bool write_fault,
		      bool *writable);
unsigned long gfn_to_hva_memslot_prot(struct kvm_memory_slot *slot, gfn_t gfn,
				      bool *writable);
kvm_pfn_t mini__gfn_to_pfn_memslot(const struct kvm_memory_slot *slot, gfn_t gfn,
			       bool atomic, bool interruptible, bool *async,
			       bool write_fault, bool *writable, hva_t *hva);

void mini_release_pfn_clean(kvm_pfn_t pfn);
void mini_set_pfn_accessed(kvm_pfn_t pfn);

int mini_write_guest_page(struct mini *mini, gfn_t gfn, const void *data,
			 int offset, int len);
int mini_write_guest(struct mini *mini, gpa_t gpa, const void *data,
		    unsigned long len);

void mini_flush_remote_tlbs(struct mini *mini);

bool mini_vcpu_wake_up(struct mini_vcpu *vcpu);

static inline struct rcuwait *mini_arch_vcpu_get_wait(struct mini_vcpu *vcpu)
{
#ifdef __KVM_HAVE_ARCH_WQP
	return vcpu->arch.waitp;
#else
	return &vcpu->wait;
#endif //__KVM_HVAE_ARCH_WQP
}

static inline bool __mini_vcpu_wake_up(struct mini_vcpu *vcpu)
{
	return !!rcuwait_wake_up(mini_arch_vcpu_get_wait(vcpu));
}


#ifdef KVM_ARCH_NR_OBJS_PER_MEMORY_CACHE
int mini_mmu_topup_memory_cache(struct kvm_mmu_memory_cache *mc, int min);
int __mini_mmu_topup_memory_cache(struct kvm_mmu_memory_cache *mc, int capacity, int min);
int mini_mmu_memory_cache_nr_free_objects(struct kvm_mmu_memory_cache *mc);
void mini_mmu_free_memory_cache(struct kvm_mmu_memory_cache *mc);
void *mini_mmu_memory_cache_alloc(struct kvm_mmu_memory_cache *mc);
#endif //KVM_ARCH_NR_OBJS_PER_MEMOY_CACH

static inline int mini_memslot_id(struct mini *mini, gfn_t gfn)
{
	return mini_gfn_to_memslot(mini, gfn)->id;
}

#ifdef CONFIG_KVM_GENERIC_DIRTYLOG_READ_PROTECT
void mini_arch_flush_remote_tlbs_memslot(struct mini *mini,
					const struct kvm_memory_slot *memslot);
#else // !CONFIG_KVM_GENERIC_DIRTYLOG_READ_PROTECT 

int mini_vm_ioctl_get_dirty_log(struct mini *mini, struct mini_dirty_log *log);
int mini_get_dirty_log(struct mini *mini, struct mini_dirty_log *log,
		      int *is_dirty, struct kvm_memory_slot **memslot);
#endif //CONFIG_KVM_GENERIC_DIRTYLOG_READ_PROTECT

vm_fault_t mini_arch_vcpu_fault(struct mini_vcpu *vcpu, struct vm_fault *vmf);
int mini_arch_vcpu_create(struct mini_vcpu *vcpu);
void mini_arch_vcpu_destroy(struct mini_vcpu *vcpu);

#if defined(CONFIG_MMU_NOTIFIER) && defined(KVM_ARCH_WANT_MMU_NOTIFIER)
static inline int mini_mmu_invalidate_retry(struct mini *mini, unsigned long mmu_seq)
{
	if (unlikely(mini->mmu_invalidate_in_progress))
		return 1;
	/*
	 * Ensure the read of mmu_invalidate_in_progress happens before
	 * the read of mmu_invalidate_seq.  This interacts with the
	 * smp_wmb() in mmu_notifier_invalidate_range_end to make sure
	 * that the caller either sees the old (non-zero) value of
	 * mmu_invalidate_in_progress or the new (incremented) value of
	 * mmu_invalidate_seq.
	 *
	 * PowerPC Book3s HV KVM calls this under a per-page lock rather
	 * than under mini->mmu_lock, for scalability, so can't rely on
	 * mini->mmu_lock to keep things ordered.
	 */
	smp_rmb();
	if (mini->mmu_invalidate_seq != mmu_seq)
		return 1;
	return 0;
}

static inline int mini_mmu_invalidate_retry_hva(struct mini *mini,
					   unsigned long mmu_seq,
					   unsigned long hva)
{
	lockdep_assert_held(&mini->mmu_lock);
	/*
	 * If mmu_invalidate_in_progress is non-zero, then the range maintained
	 * by mini_mmu_notifier_invalidate_range_start contains all addresses
	 * that might be being invalidated. Note that it may include some false
	 * positives, due to shortcuts when handing concurrent invalidations.
	 */
	if (unlikely(mini->mmu_invalidate_in_progress) &&
	    hva >= mini->mmu_invalidate_range_start &&
	    hva < mini->mmu_invalidate_range_end)
		return 1;
	if (mini->mmu_invalidate_seq != mmu_seq)
		return 1;
	return 0;
}
#endif //defined(CONFIG_MMU_NOTIFIER) && defined(KVM_ARCH_WANT_MMU_NOTIFIER)
       
#endif //__KVM_HOST_H
