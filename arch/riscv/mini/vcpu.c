#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/mini_host.h>
//#include <linux/kvm_host.h>
#include <asm/hwcap.h>
#include <asm/sbi.h>

/*
#define MINI_ISA_EXT_ARR(ext)		[MINI_RISCV_ISA_EXT_##ext] = RISCV_ISA_EXT_##ext

// Mapping between MINI ISA Extension ID & Host ISA extension ID 
static const unsigned long mini_isa_ext_arr[] = {
	[MINI_RISCV_ISA_EXT_A] = RISCV_ISA_EXT_a,
	[MINI_RISCV_ISA_EXT_C] = RISCV_ISA_EXT_c,
	[MINI_RISCV_ISA_EXT_D] = RISCV_ISA_EXT_d,
	[MINI_RISCV_ISA_EXT_F] = RISCV_ISA_EXT_f,
	[MINI_RISCV_ISA_EXT_H] = RISCV_ISA_EXT_h,
	[MINI_RISCV_ISA_EXT_I] = RISCV_ISA_EXT_i,
	[MINI_RISCV_ISA_EXT_M] = RISCV_ISA_EXT_m,

	MINI_ISA_EXT_ARR(SSAIA),
	MINI_ISA_EXT_ARR(SSTC),
	MINI_ISA_EXT_ARR(SVINVAL),
	MINI_ISA_EXT_ARR(SVPBMT),
	MINI_ISA_EXT_ARR(ZBB),
	MINI_ISA_EXT_ARR(ZIHINTPAUSE),
	MINI_ISA_EXT_ARR(ZICBOM),
	MINI_ISA_EXT_ARR(ZICBOZ),
};
*/

const struct _mini_stats_desc mini_vcpu_stats_desc[] = {
	MINI_GENERIC_VCPU_STATS(),
	STATS_DESC_COUNTER(VCPU, ecall_exit_stat),
	STATS_DESC_COUNTER(VCPU, wfi_exit_stat),
	STATS_DESC_COUNTER(VCPU, mmio_exit_user),
	STATS_DESC_COUNTER(VCPU, mmio_exit_kernel),
	STATS_DESC_COUNTER(VCPU, csr_exit_user),
	STATS_DESC_COUNTER(VCPU, csr_exit_kernel),
	STATS_DESC_COUNTER(VCPU, signal_exits),
	STATS_DESC_COUNTER(VCPU, exits)
};

const struct mini_stats_header mini_vcpu_stats_header = {
	.name_size = MINI_STATS_NAME_SIZE,
	.num_desc = ARRAY_SIZE(mini_vcpu_stats_desc),
	.id_offset = sizeof(struct mini_stats_header),
	.desc_offset = sizeof(struct mini_stats_header) + MINI_STATS_NAME_SIZE,
	.data_offset = sizeof(struct mini_stats_header) + MINI_STATS_NAME_SIZE +
		       sizeof(mini_vcpu_stats_desc),
};


#define MINI_ISA_EXT_ARR(ext)		[MINI_RISCV_ISA_EXT_##ext] = RISCV_ISA_EXT_##ext

/* Mapping between MINI ISA Extension ID & Host ISA extension ID */
static const unsigned long mini_isa_ext_arr[] = {
	[MINI_RISCV_ISA_EXT_A] = RISCV_ISA_EXT_a,
	[MINI_RISCV_ISA_EXT_C] = RISCV_ISA_EXT_c,
	[MINI_RISCV_ISA_EXT_D] = RISCV_ISA_EXT_d,
	[MINI_RISCV_ISA_EXT_F] = RISCV_ISA_EXT_f,
	[MINI_RISCV_ISA_EXT_H] = RISCV_ISA_EXT_h,
	[MINI_RISCV_ISA_EXT_I] = RISCV_ISA_EXT_i,
	[MINI_RISCV_ISA_EXT_M] = RISCV_ISA_EXT_m,

	MINI_ISA_EXT_ARR(SSAIA),
	MINI_ISA_EXT_ARR(SSTC),
	MINI_ISA_EXT_ARR(SVINVAL),
	MINI_ISA_EXT_ARR(SVPBMT),
	MINI_ISA_EXT_ARR(ZBB),
	MINI_ISA_EXT_ARR(ZIHINTPAUSE),
	MINI_ISA_EXT_ARR(ZICBOM),
	MINI_ISA_EXT_ARR(ZICBOZ),
};

static bool mini_riscv_vcpu_isa_enable_allowed(unsigned long ext)
{
	switch (ext) {
	case MINI_RISCV_ISA_EXT_H:
		return false;
	default:
		break;
	}

	return true;
}

vm_fault_t mini_arch_vcpu_fault(struct mini_vcpu *vcpu, struct vm_fault *vmf)
{
	return VM_FAULT_SIGBUS;
}

int mini_arch_vcpu_create(struct mini_vcpu *vcpu)
{
	int rc;
	struct mini_cpu_context *cntx;
	struct mini_vcpu_csr *reset_csr = &vcpu->arch.guest_reset_csr;
	unsigned long host_isa, i;

    mini_info("[mini] mini_arch_vcpu_create\n");
	/* Mark this VCPU never ran */
	vcpu->arch.ran_atleast_once = false;
	vcpu->arch.mmu_page_cache.gfp_zero = __GFP_ZERO;
	bitmap_zero(vcpu->arch.isa, RISCV_ISA_EXT_MAX);

	/* Setup ISA features available to VCPU */
	for (i = 0; i < ARRAY_SIZE(mini_isa_ext_arr); i++) {
		host_isa = mini_isa_ext_arr[i];
		if (__riscv_isa_extension_available(NULL, host_isa) &&
		    mini_riscv_vcpu_isa_enable_allowed(i))
			set_bit(host_isa, vcpu->arch.isa);
	}

	/* Setup vendor, arch, and implementation details */
	vcpu->arch.mvendorid = sbi_get_mvendorid();
	vcpu->arch.marchid = sbi_get_marchid();
	vcpu->arch.mimpid = sbi_get_mimpid();

	/* Setup VCPU hfence queue */
	spin_lock_init(&vcpu->arch.hfence_lock);

	/* Setup reset state of shadow SSTATUS and HSTATUS CSRs */
	cntx = &vcpu->arch.guest_reset_context;
	cntx->sstatus = SR_SPP | SR_SPIE;
	cntx->hstatus = 0;
	cntx->hstatus |= HSTATUS_VTW;
	cntx->hstatus |= HSTATUS_SPVP;
	cntx->hstatus |= HSTATUS_SPV;

	/* By default, make CY, TM, and IR counters accessible in VU mode */
	reset_csr->scounteren = 0x7;

	/* Setup VCPU timer */
	//mini_riscv_vcpu_timer_init(vcpu);

	/* setup performance monitoring */
	//mini_riscv_vcpu_pmu_init(vcpu);
	if (rc)
		return rc;

	/* Reset VCPU */
	//mini_riscv_reset_vcpu(vcpu);

	return 0;
}
