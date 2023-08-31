#include <linux/mini_host.h>
#include <linux/module.h>
#include <linux/hugetlb.h>

#include <asm/csr.h>
#include <asm/page.h>
#include <asm/pgtable.h>

#ifdef CONFIG_64BIT
static unsigned long gstage_mode __ro_after_init = (HGATP_MODE_SV39X4 << HGATP_MODE_SHIFT);
static unsigned long gstage_pgd_levels __ro_after_init = 3;
#define gstage_index_bits	9
#else
static unsigned long gstage_mode __ro_after_init = (HGATP_MODE_SV32X4 << HGATP_MODE_SHIFT);
static unsigned long gstage_pgd_levels __ro_after_init = 2;
#define gstage_index_bits	10
#endif

#define gstage_pgd_xbits	2
#define gstage_pgd_size	(1UL << (HGATP_PAGE_SHIFT + gstage_pgd_xbits))
#define gstage_gpa_bits	(HGATP_PAGE_SHIFT + \
			 (gstage_pgd_levels * gstage_index_bits) + \
			 gstage_pgd_xbits)
#define gstage_gpa_size	((gpa_t)(1ULL << gstage_gpa_bits))

#define gstage_pte_leaf(__ptep)	\
	(pte_val(*(__ptep)) & (_PAGE_READ | _PAGE_WRITE | _PAGE_EXEC))

int mini_riscv_gstage_alloc_pgd(struct mini *mini)
{
	struct page *pgd_page;

    mini_info("mini_riscv_gstage_alloc_pgd\n");

	if (mini->arch.pgd != NULL) {
		mini_err("mini_arch already initialized?\n");
		return -EINVAL;
	}

	pgd_page = alloc_pages(GFP_KERNEL | __GFP_ZERO,
				get_order(gstage_pgd_size));
	if (!pgd_page)
		return -ENOMEM;
	mini->arch.pgd = page_to_virt(pgd_page);
	mini->arch.pgd_phys = page_to_phys(pgd_page);

    mini_info("\t[mini_riscv_gstage_alloc_pgd] pgd_page : 0x%lx\n", pgd_page);
    mini_info("\t[mini_riscv_gstage_alloc_pgd] pgd_virt : 0x%lx\n", mini->arch.pgd);
    mini_info("\t[mini_riscv_gstage_alloc_pgd] pgd_phys : 0x%lx\n", mini->arch.pgd_phys);
    
    mini_info("\t[mini_riscv_gstage_alloc_pgd] pgd_page : 0x%lx\n", *pgd_page);
    mini_info("\t[mini_riscv_gstage_alloc_pgd] pgd_virt : 0x%lx\n", *mini->arch.pgd);

    return 0;
}

void mini_riscv_gstage_free_pgd(struct mini *mini)
{
	void *pgd = NULL;

    /*
	spin_lock(&mini->mmu_lock);
	if (mini->arch.pgd) {
		gstage_unmap_range(mini, 0UL, gstage_gpa_size, false);
		pgd = READ_ONCE(mini->arch.pgd);
		mini->arch.pgd = NULL;
		mini->arch.pgd_phys = 0;
	}
	spin_unlock(&mini->mmu_lock);
    */

    pgd = mini->arch.pgd;
	if (pgd)
		free_pages((unsigned long)pgd, get_order(gstage_pgd_size));
}

void mini_riscv_gstage_update_hgatp(struct mini *mini)
{
	unsigned long hgatp = gstage_mode;
	struct mini_arch *k = &(mini->arch);

    mini_info("mini_riscv_gstage_update_hgatp\n");
    mini_info("hgatp : 0x%x\n", hgatp);

	hgatp |= (READ_ONCE(k->vmid.vmid) << HGATP_VMID_SHIFT) & HGATP_VMID;
	hgatp |= (k->pgd_phys >> PAGE_SHIFT) & HGATP_PPN;

    mini_info("hgatp : 0x%x\n", hgatp);

	csr_write(CSR_HGATP, hgatp);

	if (!mini_riscv_gstage_vmid_bits())
	    asm volatile(HFENCE_GVMA(zero, zero) : : : "memory");
}
