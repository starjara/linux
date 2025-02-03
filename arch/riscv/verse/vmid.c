#include <linux/module.h>
#include <linux/verse_host.h>

static unsigned long vmid_bits __ro_after_init;
static unsigned long vmidindex = 0;

unsigned long verse_riscv_gstage_vmid_bits(void)
{
  return vmid_bits;
}

int verse_riscv_gstage_vmid_init(struct verse *verse)
{
  verse->arch.vmid.vmid_version = 512;
  verse->arch.vmid.vmid = vmidindex ++;

  return 0;
}
