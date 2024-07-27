#include <linux/module.h>
#include <linux/verse_host.h>

int verse_arch_init_vm(struct verse *verse)
{
  int r;

  // verse_info("\t[verse] verse_arch_init_vm\n");

  r = verse_riscv_gstage_alloc_pgd(verse);
  if(r)
    return r;

  r = verse_riscv_gstage_vmid_init(verse);
  if(r) {
    verse_error("\t[verse] vmit init failed\n");
    verse_riscv_gstage_free_pgd(verse);
  }
  
  return 0;
}

void verse_arch_destroy_vm(struct verse *verse) {
  return ;
}

void verse_arch_enter_vm(struct verse *verse) {
  verse_riscv_gstage_update_hgatp(verse);
}

void verse_arch_exit_vm() {
  csr_write(CSR_HGATP, 0x0);
  asm volatile(HFENCE_GVMA(zero, zero) : : : "memory");
}
