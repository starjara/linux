#include <linux/mini_host.h>
#include <asm/csr.h>

static unsigned long vmid_bits __ro_after_init;

unsigned long mini_riscv_gstage_vmid_bits(void)
{
	return vmid_bits;
}

int mini_riscv_gstage_vmid_init(struct mini *mini)
{
	/* Mark the initial VMID and VMID version invalid */
	mini->arch.vmid.vmid_version = 0;
	mini->arch.vmid.vmid = 0;

	return 0;
}

