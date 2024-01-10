#include <linux/module.h>
#include <linux/mini_host.h>

static int __init riscv_mini_init(void)
{
    int rc = 0;

    mini_info("hello mini!\n");

    rc = mini_init(sizeof(struct mini_vcpu), 0, THIS_MODULE);
    return rc; 
}
module_init(riscv_mini_init);

static void __exit riscv_mini_exit(void)
{
    mini_exit();
}
module_exit(riscv_mini_exit);
