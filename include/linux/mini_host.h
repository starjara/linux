#ifndef __MINI_HOST_H
#define __MINI_HOST_H

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/rbtree.h>
#include <linux/hashtable.h>

#include <linux/mini_types.h>

#include <asm/mini_host.h>

#define MINI_ADDRESS_SPACE_NUM  1


#define mini_err(fmt, ...) \
    pr_err("mini [%i]: " fmt, task_pid_nr(current), ## __VA_ARGS__)
#define mini_info(fmt, ...) \
    pr_info("mini [%i]: " fmt, task_pid_nr(current), ## __VA_ARGS__)

struct mvm {
    int vmid;
};

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
#ifdef KVM_HAVE_MMU_RWLOCK
	rwlock_t mmu_lock;
#else
	spinlock_t mmu_lock;
#endif /* KVM_HAVE_MMU_RWLOCK */

    struct mini_arch arch;
	struct mini_memslots __memslots[MINI_ADDRESS_SPACE_NUM][2];
    char stats_id[MINI_STATS_NAME_SIZE];
};

static inline void *mini_arch_alloc_vm(void)
{
    return kzalloc(sizeof(struct mvm), GFP_KERNEL_ACCOUNT);
}

int mini_init(unsigned size, unsigned align, struct module *module);
void mini_exit(void);

int mini_arch_init_vm(struct mini *mini, unsigned long type);

int mini_arch_enter(struct mini *mini);

#endif
