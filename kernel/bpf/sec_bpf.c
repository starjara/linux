#include <linux/sec_bpf.h>
#include <linux/filter.h>
#include <linux/highmem.h>
#include <linux/mm.h>

#include <asm/pgtable.h>
#include <asm/cpufeature.h>
#include <asm/pgalloc.h>

/* JARA: Debug print format */
#define LOG_E pr_info("[kernel/bpf/sec_bpf.c] Enter: %s\n", __func__)
#define SEC_PRINT(fmt, ...) pr_info("[kernel/bpf/sec_bpf.c] %s: " fmt "\n", __func__, ##__VA_ARGS__)
/* End JARA */

int alloc_bpf_pgd(struct bpf_prog *prog)
{
  unsigned long long ttbr0 = read_sysreg(ttbr0_el1);
  unsigned long long ttbr1 = read_sysreg(ttbr1_el1);
  pgd_t *kern_pgd = (pgd_t *)phys_to_virt(ttbr1);

  int i;
  
  
  LOG_E;

  if(prog->pgd != NULL) {
    SEC_PRINT("PGD Already allocated\n");
    return -1;
  }
  
  //prog->pgd = (pgd_t *)__get_free_page(GFP_PGTABLE_USER);
  prog->pgd = (pgd_t *)__get_free_page(GFP_PGTABLE_KERNEL);
  prog->pgd = kern_pgd;
  
  if(prog->pgd == NULL) {
    SEC_PRINT("PGD Alloc failed");
    return -1;
  }

  SEC_PRINT("TTBR0_EL1: 0x%lx\n", ttbr0);
  SEC_PRINT("TTBR1_EL1: 0x%lx\n", ttbr1);
  SEC_PRINT("TTBR1_EL1_BASE: 0x%lx\n", ((ttbr1) & 0x0000FFFFFFFFFFFF));
  SEC_PRINT("TTBR1_EL1_VIRT: 0x%lx\n", kern_pgd);
  SEC_PRINT("NEW_PGD_VIRT: 0x%lx\n", prog->pgd);
  SEC_PRINT("NEW_PGD_PHYS: 0x%lx\n", virt_to_phys(prog->pgd));
  SEC_PRINT("TCR_EL1: 0x%lx\n", read_sysreg(tcr_el1));
  SEC_PRINT("SPSel: 0x%lx\n", read_sysreg(spsel));
   
  memcpy(prog->pgd, kern_pgd, PAGE_SIZE);
  
  if(memcmp(prog->pgd, kern_pgd, PAGE_SIZE) == 0) {
    SEC_PRINT("Copy successfully\n");
  }
  else {
    SEC_PRINT("Copy failed\n");
    return -1;
  }

  SEC_PRINT("\t\tADDR\tVALUE");
  
  /* Table walking */
  int j, k, l;
  for(i=0; i<257; i++) {
    u64 old_pgd_entry = (u64)(kern_pgd + i);
    u64 new_pgd_entry = (u64)(prog->pgd + i);
    pgd_t *pgd_entry = kern_pgd + i;
    int is_readonly = ((pgd_entry->pgd >> 0x07) & 0x01) ? 1 : 0;
   
  /*
    SEC_PRINT("Kernel PGD[%d]: 0x%lx\t0x%lx", i, kern_pgd + i, *(kern_pgd + i));
  */

    if(pgd_entry->pgd != 0 && !is_readonly) {
      SEC_PRINT("Coppied PGD[%d]: 0x%lx\t0x%lx", i, pgd_entry, pgd_entry->pgd); 

      for(j=0; j<512; j++) {
	pud_t *pud_entry = phys_to_virt((((pgd_entry->pgd) & ((1 << 48) - 1)) >> 12)<<12);
	int is_readonly = ((pud_entry->pud >> 0x07) & 0x01) ? 1 : 0;
	pud_entry += j;
	
	if(pud_entry->pud != 0 && !is_readonly) {
	  SEC_PRINT("\tCoppied PUD[%d]: 0x%lx\t0x%lx", j, pud_entry, pud_entry->pud); 

	  for(k=0; k<512; k++) {
	    pmd_t *pmd_entry = phys_to_virt(((pud_entry->pud & ((1 << 48) - 1)) >> 12) << 12);
	    int is_readonly = ((pmd_entry->pmd >> 0x07) & 0x01) ? 1 : 0;
	    pmd_entry += k;

	    if(pmd_entry->pmd != 0 && !is_readonly){
	      SEC_PRINT("\t\tCoppied PMD[%d]: 0x%lx\t0x%lx", k, pmd_entry , pmd_entry->pmd); 

	      for(l=0; l<512; l++) {
		pte_t *pte_entry = phys_to_virt(((pmd_entry->pmd & ((1 << 48) - 1)) >> 12) << 12);
		int is_readonly = ((pmd_entry->pmd >> 0x07) & 0x01) ? 1 : 0;
		pte_entry += l;

		if(pte_entry->pte != 0 && !is_readonly) {
		  if((pte_entry->pte & 0x1) == 0x1) {
		    //SEC_PRINT("\t\t\tCoppied PTE[%d]: 0x%lx\t0x%lx", l, pte_entry , pte_entry->pte); 
		    pte_entry->pte |= 0x40;
		    //SEC_PRINT("\t\t\tCoppied PTE[%d]: 0x%lx\t0x%lx", l, pte_entry , pte_entry->pte); 
		  }
		}
	      }
	      //pmd_entry->pmd |= 0x40;
	    }
	  }
	  //pud_entry->pud |= 0x40;
	}
      }
      //pgd_entry->pgd |= 0x40;
    }
    //SEC_PRINT("Coppied PGD[%d]: 0x%lx\t0x%lx", i, prog->pgd + i, *(prog->pgd + i)); 
  }
  /* Table walking end */
   
  

  return 0;
}
