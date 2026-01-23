#include <linux/mm.h>
#include <linux/bpf.h>

#include <asm/csr.h>
#include <asm/page.h>
#include <asm/pgtable.h>

#include "gbpf.h"
#include "gbpf_mmu.h"

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

/* Garden Start -> Managing Packet(Not using now)
static int gbpf_map_packet(struct bpf_prog *prog, void *skb_data, size_t len){
	unsigned long phys_addr = virt_to_phys(skb_data);
	unsigned long vaddr = BPF_PACKET_START_ADDR;

	// phys_addr >> PAGE_SHIFT : translating Physical Address to PFN 
	set_pte_at(prog->gpgd, vaddr, pte_ptr, pfn_pte(phys_addr >> PAGE_SHIFT, PAGE_READONLY));

	return 0;
}
Garden End */


/* Garden Start : Called when no arguments are passed */
void gbpf_init_basic_mappings(struct bpf_prog *prog){	
	unsigned long code_vaddr = (unsigned long)prog->insnsi;
	unsigned long code_phys = virt_to_phys(prog->insnsi);
	pte_t *ptep;
	gbpf_info("Hello basic mapping!\n");
	ptep = gbpf_get_pte_ptr(prog->gpgd, code_vaddr);
	if (ptep){
		*ptep = pfn_pte(code_phys >> PAGE_SHIFT, PAGE_KERNEL_RO);
	}
/*
	if(prog->aux->stack_depth){
		unsigned long stack_vaddr = (unsigned long)prog->aux->stack_depth;
		unsigned long stack_phys = virt_to_phys(prog->aux->stack_depth);

		ptep = gbpf_get_pte_ptr(prog->gpgd, stack_vaddr);
		if(ptep){
			set_pte_at(&init_mm, stack_vaddr, ptep, pfn_pte(stack_phys >> PAGE_SHIFT, PAGE_KERNEL_RO));
		}

	}
*/
}
EXPORT_SYMBOL_GPL(gbpf_init_basic_mappings);


int gbpf_map_private_data(struct bpf_prog *prog, unsigned long vaddr)
{
	struct page *private_page;
	pte_t *ptep;
	unsigned long pfn;

	private_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!private_page){
		gbpf_err("Failed to allocate 4KB private data page\n");
		return -ENOMEM;
	}

	ptep = gbpf_get_pte_ptr(prog->gpgd, vaddr);
	if (!ptep) {
		gbpf_info("Failed to get PTE pointer for vaddr : %lx\n", vaddr);
		__free_page(private_page);
		return -ENOMEM;
	}

	pfn = page_to_pfn(private_page);
	set_pte(ptep, pfn_pte(pfn, __pgprot(_PAGE_PRESENT | _PAGE_READ | _PAGE_WRITE)));

	gbpf_info("Mapped 4KB page (PFN: %lx) to BPF vaddr: %lx\n", pfn, vaddr);

	return 0;
}
EXPORT_SYMBOL_GPL(gbpf_map_private_data);




/* Garden : Allocating Table */
static void *gbpf_alloc_table(void){
	gbpf_info("Allocating Table -> gbpf_alloc_table\n");
	struct page *p = alloc_pages(GFP_KERNEL | __GFP_ZERO, 0);
	if (!p) return NULL;
	return page_to_virt(p);
}

/* Garden : Making L2 ~ L4 page tables */
pte_t *gbpf_get_pte_ptr(void *gpgd, unsigned long vaddr){
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	pgd = (pgd_t *)gpgd + pgd_index(vaddr);
	if (pgd_none(*pgd)){
		void *new_p4d = gbpf_alloc_table();
		if (!new_p4d) return NULL;

		set_pgd(pgd, pfn_pgd(virt_to_phys(new_p4d) >> PAGE_SHIFT, __pgprot(_PAGE_TABLE)));
		pr_info("[gBPF] Allocated new P4D table\n");
	}

	gbpf_info("Making p4d\n");
	p4d = p4d_offset(pgd, vaddr);
	if (p4d_none(*p4d)){
		void *new_pud = gbpf_alloc_table();
		set_p4d(p4d, pfn_p4d(virt_to_phys(new_pud) >> PAGE_SHIFT , __pgprot(_PAGE_TABLE))); /* not riscv kernel function? */
	}

	gbpf_info("Making pud\n");
	pud = pud_offset(p4d, vaddr);
	if (pud_none(*pud)){
		void *new_pmd = gbpf_alloc_table();
		set_pud(pud, pfn_pud(virt_to_phys(new_pmd) >> PAGE_SHIFT, __pgprot(_PAGE_TABLE)));
	}

	gbpf_info("Making pmd\n");
	pmd = pmd_offset(pud, vaddr);
   	if (pmd_none(*pmd)) {
        
	void *new_pte = gbpf_alloc_table();
        set_pmd(pmd, pfn_pmd(virt_to_phys(new_pte) >> PAGE_SHIFT, __pgprot(_PAGE_TABLE))); // PMD 칸에 새 PTE 연결
    }

	return pte_offset_kernel(pmd, vaddr);
}
EXPORT_SYMBOL_GPL(gbpf_get_pte_ptr);



static int gbpf_alloc_gpgd(struct bpf_prog *prog)
{
  struct page *pgd_page;
  
  gbpf_info("[%s] - Allocate gpgd\n", __func__);

  if (prog->gpgd) {
    gbpf_err("[%s] - gpgd alraedy allocated\n", __func__);
    gbpf_err("\t%p\n", prog->gpgd);
    return -EINVAL;
  }

  pgd_page = alloc_pages(GFP_KERNEL | __GFP_ZERO, get_order(gstage_pgd_size));

  if (!pgd_page)
    return -ENOMEM;

  prog->gpgd = page_to_virt(pgd_page);

  /* Garden : add -> But Do not modify this function. 
  if (prog->insnsi){
	  gbpf_get_pte_ptr(prog->gpgd, 0xf000000000);
	  gbpf_info("[%s] - Pre-allocated L2-L4 paths for BPF code\n", __func__);
  }
  */
  return 0;
}

int gbpf_create_pgtable(struct bpf_prog *prog)
{
  int ret = 0;
  
  gbpf_info("Create a pgtable\n");
  
  ret = gbpf_alloc_gpgd(prog);

  if (ret != 0) {
    gbpf_err("[%s] - pgd allocation failed\n", __func__);
    return ret;
  }

  return ret;
}
EXPORT_SYMBOL_GPL(gbpf_create_pgtable);


void gbpf_free_all_levels(void *table, int level){
	if (level >= 4) return;

	if (!table) return;

	for (int i = 0; i < 512; i++){
		unsigned long entry = ((unsigned long *)table)[i];

		if(entry & _PAGE_PRESENT) {
			void *next_table = __va(pte_pfn(__pte(entry)) << PAGE_SHIFT);

			gbpf_free_all_levels(next_table, level + 1);
			gbpf_info("Trying to free page -> %p", next_table);
			free_page((unsigned long)next_table);
			gbpf_info("Successful.\n");
		}
	
	}
}
EXPORT_SYMBOL_GPL(gbpf_free_all_levels);

static void gbpf_free_gpgd(struct bpf_prog *prog)
{
  gbpf_info("[%s] - free gpgd\n", __func__);

  if (prog->gpgd)
    free_pages((unsigned long)prog->gpgd, get_order(gstage_pgd_size));

  return ;
}

void gbpf_destroy_pgtable(struct bpf_prog *prog)
{
  gbpf_info("[%s] - destroy a pgtable\n", __func__);

  gbpf_free_gpgd(prog);

  return ;
}
EXPORT_SYMBOL_GPL(gbpf_destroy_pgtable);

