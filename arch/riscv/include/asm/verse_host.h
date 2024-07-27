#ifndef __RISCV_VERSE_HOST_H__
#define __RISCV_VERSE_HOST_H__

#include <linux/verse.h>
#include <linux/verse_types.h>
#include <linux/types.h>

#define MAX_REGION_COUNT 1024

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
  struct mm_struct *mm;
};

struct verse_cpu_context {
	unsigned long zero;
	unsigned long ra;
	unsigned long sp;
	unsigned long gp;
	unsigned long tp;
	unsigned long t0;
	unsigned long t1;
	unsigned long t2;
	unsigned long s0;
	unsigned long s1;
	unsigned long a0;
	unsigned long a1;
	unsigned long a2;
	unsigned long a3;
	unsigned long a4;
	unsigned long a5;
	unsigned long a6;
	unsigned long a7;
	unsigned long s2;
	unsigned long s3;
	unsigned long s4;
	unsigned long s5;
	unsigned long s6;
	unsigned long s7;
	unsigned long s8;
	unsigned long s9;
	unsigned long s10;
	unsigned long s11;
	unsigned long t3;
	unsigned long t4;
	unsigned long t5;
	unsigned long t6;
	unsigned long sepc;
	unsigned long sstatus;
	unsigned long hstatus;
	union __riscv_fp_state fp;
};

struct verse_arch {
  // G-stage vmid, not implemented
  struct verse_vmid vmid;

  // G-stage page table
  pgd_t *pgd;
  phys_addr_t pgd_phys;

  // G-stage mapped regions
  struct verse_riscv_memregion *regions[MAX_REGION_COUNT];

  // Register contexts
  // struct verse_cpu_context host_context;
  // struct verse_cpu_context guest_context;
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
