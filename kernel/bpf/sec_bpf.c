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
  
  LOG_E;

  if(prog->pgd != NULL) {
    SEC_PRINT("PGD Already allocated\n");
    return -1;
  }
  
  //prog->pgd = (pgd_t *)__get_free_page(GFP_PGTABLE_USER);
  prog->pgd = (pgd_t *)__get_free_page(GFP_PGTABLE_KERNEL);

  SEC_PRINT("TTBR0_EL1: 0x%lx\n", ttbr0);
  SEC_PRINT("TTBR1_EL1: 0x%lx\n", ttbr1);
  
  memcpy(prog->pgd, kern_pgd, sizeof(PAGE_SIZE));
  if(memcmp(prog->pgd, kern_pgd, sizeof(PAGE_SIZE)) == 0) {
    SEC_PRINT("Copy successfully\n");
  }
  else {
    SEC_PRINT("Copy failed\n");
  }

  return 0;
}
