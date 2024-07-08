#ifndef __RISCV_VERSE_HOST_H__
#define __RISCV_VERSE_HOST_H__

#include <linux/verse.h>
#include <linux/verse_types.h>

#define MAX_REGION_COUNT 10

// Structs
struct verse_vmid {
	/*
	 * Writes to vmid_version and vmid happen with vmid_lock held
	 * whereas reads happen without any lock held.
	 */
	unsigned long vmid_version;
	unsigned long vmid;
};

struct verse_riscv_memregion {
  __u64 guest_phys_addr;
  __u64 memory_size;
  __u64 userspace_virtual_addr;
  __u64 kernel_virtual_addr;
  __u64 phys_addr;
};

struct verse_arch {
  // G-stage vmid, not implemented
  struct verse_vmid vmid;

  // G-stage page table
  pgd_t *pgd;
  phys_addr_t pgd_phys;

  // G-stage mapped regions
  struct verse_riscv_memregion *regions[MAX_REGION_COUNT];
};

// Functions

// MMU
int verse_riscv_gstage_alloc_pgd(struct verse *verse);
void verse_riscv_gstage_free_pgd(struct verse *verse);
void verse_riscv_gstage_update_hgatp(struct verse *verse);
int verse_riscv_gstage_map(struct verse *verse);

// VMID
unsigned long verse_riscv_gstage_vmid_bits(void);
int verse_riscv_gstage_vmid_init(struct verse *verse);

#endif // __RISCV_VERSE_HOST_H__
