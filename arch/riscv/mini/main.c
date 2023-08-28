#include <linux/module.h>
#include <linux/mini_host.h>

static int __init riscv_mini_init(void)
{
    mini_info("hello mini!\n");
    return 0;
}
module_init(riscv_mini_init);
