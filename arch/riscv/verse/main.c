#include <linux/module.h>
#include <linux/verse_host.h>

static int __init riscv_verse_init(void)
{
  int rc = 0;

  verse_info("[verse_arch] riscv_verse_init\n");

  rc = verse_init(1024, THIS_MODULE);

  return rc;
}
module_init(riscv_verse_init);

static void __exit riscv_verse_exit(void)
{
  verse_exit();
}
module_exit(riscv_verse_exit);
