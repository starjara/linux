#include <linux/module.h>
#include <linux/mini_host.h>

int mini_arch_init_vm(struct mini *mini, unsigned long type)
{
    int r;

    mini_info("mini_arch_init_vm\n");

	r = mini_riscv_gstage_alloc_pgd(mini);
    if(r)
        return r;

    r = mini_riscv_gstage_vmid_init(mini);
    if(r) {
        mini_riscv_gstage_free_pgd(mini);
    }

    return 0;
}

int mini_arch_enter(struct mini *mini)
{
    mini_riscv_gstage_update_hgatp(mini);
    return 0;
}
