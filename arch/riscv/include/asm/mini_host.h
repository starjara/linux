#ifndef __RISCV_MINI_HOST_H__
#define __RISCV_MINI_HOST_H__

#include <linux/types.h>
#include <linux/mini.h>
#include <linux/mini_types.h>

#define MINI_MAX_VCPUS			1024

#define MINI_REQ_SLEEP \
	MINI_ARCH_REQ_FLAGS(0, MINI_REQUEST_WAIT | MINI_REQUEST_NO_WAKEUP)
#define MINI_REQ_VCPU_RESET		MINI_ARCH_REQ(1)
#define MINI_REQ_UPDATE_HGATP		MINI_ARCH_REQ(2)
#define MINI_REQ_FENCE_I			\
	MINI_ARCH_REQ_FLAGS(3, MINI_REQUEST_WAIT | MINI_REQUEST_NO_WAKEUP)
#define MINI_REQ_HFENCE_GVMA_VMID_ALL	MINI_REQ_TLB_FLUSH
#define MINI_REQ_HFENCE_VVMA_ALL		\
	MINI_ARCH_REQ_FLAGS(4, MINI_REQUEST_WAIT | MINI_REQUEST_NO_WAKEUP)
#define MINI_REQ_HFENCE			\
	MINI_ARCH_REQ_FLAGS(5, MINI_REQUEST_WAIT | MINI_REQUEST_NO_WAKEUP)

enum mini_riscv_hfence_type {
	MINI_RISCV_HFENCE_UNKNOWN = 0,
	MINI_RISCV_HFENCE_GVMA_VMID_GPA,
	MINI_RISCV_HFENCE_VVMA_ASID_GVA,
	MINI_RISCV_HFENCE_VVMA_ASID_ALL,
	MINI_RISCV_HFENCE_VVMA_GVA,
};

struct mini_riscv_hfence {
	enum mini_riscv_hfence_type type;
	unsigned long asid;
	unsigned long order;
	gpa_t addr;
	gpa_t size;
};

#define MINI_RISCV_VCPU_MAX_HFENCE	64

struct mini_vm_stat {
	struct mini_vm_stat_generic generic;
};

struct mini_vcpu_stat {
	struct mini_vcpu_stat_generic generic;
	u64 ecall_exit_stat;
	u64 wfi_exit_stat;
	u64 mmio_exit_user;
	u64 mmio_exit_kernel;
	u64 csr_exit_user;
	u64 csr_exit_kernel;
	u64 signal_exits;
	u64 exits;
};

struct mini_arch_memory_slot {
};

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
	//struct mini_guest_timer timer;

	/* AIA Guest/VM context */
	//struct mini_aia aia;
};

struct mini_cpu_context {
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

struct mini_vcpu_csr {
	unsigned long vsstatus;
	unsigned long vsie;
	unsigned long vstvec;
	unsigned long vsscratch;
	unsigned long vsepc;
	unsigned long vscause;
	unsigned long vstval;
	unsigned long hvip;
	unsigned long vsatp;
	unsigned long scounteren;
};

struct mini_vcpu_arch {
	/* VCPU ran at least once */
	bool ran_atleast_once;

	/* Last Host CPU on which Guest VCPU exited */
	int last_exit_cpu;

	/* ISA feature bits (similar to MISA) */
	DECLARE_BITMAP(isa, RISCV_ISA_EXT_MAX);

	/* Vendor, Arch, and Implementation details */
	unsigned long mvendorid;
	unsigned long marchid;
	unsigned long mimpid;

	/* SSCRATCH, STVEC, and SCOUNTEREN of Host */
	unsigned long host_sscratch;
	unsigned long host_stvec;
	unsigned long host_scounteren;

	/* CPU context of Host */
	struct mini_cpu_context host_context;

	/* CPU context of Guest VCPU */
	struct mini_cpu_context guest_context;

	/* CPU CSR context of Guest VCPU */
	struct mini_vcpu_csr guest_csr;

	/* CPU context upon Guest VCPU reset */
	struct mini_cpu_context guest_reset_context;

	/* CPU CSR context upon Guest VCPU reset */
	struct mini_vcpu_csr guest_reset_csr;

	/*
	 * VCPU interrupts
	 *
	 * We have a lockless approach for tracking pending VCPU interrupts
	 * implemented using atomic bitops. The irqs_pending bitmap represent
	 * pending interrupts whereas irqs_pending_mask represent bits changed
	 * in irqs_pending. Our approach is modeled around multiple producer
	 * and single consumer problem where the consumer is the VCPU itself.
	 */
#define MINI_RISCV_VCPU_NR_IRQS	64
	DECLARE_BITMAP(irqs_pending, MINI_RISCV_VCPU_NR_IRQS);
	DECLARE_BITMAP(irqs_pending_mask, MINI_RISCV_VCPU_NR_IRQS);

	/* VCPU Timer */
	//struct mini_vcpu_timer timer;

	/* HFENCE request queue */
	spinlock_t hfence_lock;
	unsigned long hfence_head;
	unsigned long hfence_tail;
	struct mini_riscv_hfence hfence_queue[MINI_RISCV_VCPU_MAX_HFENCE];

	/* MMIO instruction details */
	//struct mini_mmio_decode mmio_decode;

	/* CSR instruction details */
	//struct mini_csr_decode csr_decode;

	/* SBI context */
	//struct mini_vcpu_sbi_context sbi_context;

	/* AIA VCPU context */
	//struct mini_vcpu_aia aia_context;

	/* Cache pages needed to program page tables with spinlock held */
	struct mini_mmu_memory_cache mmu_page_cache;

	/* VCPU power-off state */
	bool power_off;

	/* Don't run the VCPU (blocked) */
	bool pause;

	/* Performance monitoring context */
	//struct mini_pmu pmu_context;
};

unsigned long mini_riscv_gstage_vmid_bits(void);
int mini_riscv_gstage_vmid_init(struct mini *mini);

int mini_riscv_gstage_alloc_pgd(struct mini *mini);
void mini_riscv_gstage_free_pgd(struct mini *mini);
void mini_riscv_gstage_update_hgatp(struct mini *mini);

void mini_riscv_local_hfence_gvma_vmid_gpa(unsigned long vmid,
					  gpa_t gpa, gpa_t gpsz,
					  unsigned long order);
void mini_riscv_local_hfence_gvma_vmid_all(unsigned long vmid);
void mini_riscv_local_hfence_gvma_gpa(gpa_t gpa, gpa_t gpsz,
				     unsigned long order);
void mini_riscv_local_hfence_gvma_all(void);

void mini_riscv_hfence_gvma_vmid_gpa(struct mini *mini,
				    unsigned long hbase, unsigned long hmask,
				    gpa_t gpa, gpa_t gpsz,
				    unsigned long order);
void mini_riscv_hfence_gvma_vmid_all(struct mini *mini,
				    unsigned long hbase, unsigned long hmask);

void init_mini(void);
#endif
