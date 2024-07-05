#ifndef __RISCV_VERSE_HOST_H__
#define __RISCV_VERSE_HOST_H__

#include <linux/verse.h>
#include <linux/verse_types.h>

// Structs
struct verse_vmid {
	/*
	 * Writes to vmid_version and vmid happen with vmid_lock held
	 * whereas reads happen without any lock held.
	 */
	unsigned long vmid_version;
	unsigned long vmid;
};

struct verse_arch {
  // G-stage vmid, not implemented
  struct verse_vmid vmid;

  // G-stage page table
  pgd_t *pgd;
  phys_addr_t pgd_phys;
};

// Functions

// MMU
int verse_riscv_gstage_alloc_pgd(struct verse *verse);
void verse_riscv_gstage_free_pgd(struct verse *verse);
void verse_riscv_gstage_update_hgatp(struct verse *verse);

// VMID
unsigned long verse_riscv_gstage_vmid_bits(void);
int verse_riscv_gstage_vmid_init(struct verse *verse);

#endif // __RISCV_VERSE_HOST_H__
