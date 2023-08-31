#ifndef __RISCV_MINI_HOST_H__
#define __RISCV_MINI_HOST_H__

#include <linux/types.h>
#include <linux/mini.h>
#include <linux/mini_types.h>


struct mini_vmid {
	/*
	 * Writes to vmid_version and vmid happen with vmid_lock held
	 * whereas reads happen without any lock held.
	 */
	unsigned long vmid_version;
	unsigned long vmid;
};

struct mini_arch {
	/* G-stage vmid */
	struct mini_vmid vmid;

	/* G-stage page table */
	pgd_t *pgd;
	phys_addr_t pgd_phys;

	/* Guest Timer */
	//struct kvm_guest_timer timer;

	/* AIA Guest/VM context */
	//struct kvm_aia aia;
};

unsigned long mini_riscv_gstage_vmid_bits(void);
int mini_riscv_gstage_vmid_init(struct mini *mini);

int mini_riscv_gstage_alloc_pgd(struct mini *mini);
void mini_riscv_gstage_free_pgd(struct mini *mini);
void mini_riscv_gstage_update_hgatp(struct mini *mini);



#endif
