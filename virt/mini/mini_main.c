#include <linux/module.h>
#include <linux/mini_host.h>
#include <linux/file.h>
#include <linux/debugfs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/types.h>
#include <linux/mini.h>
#include <linux/mini_types.h>
#include <linux/fs.h>
#include <linux/anon_inodes.h>

#include <asm/ioctl.h>

#define ITOA_MAX_LEN 12

#define DEVICE_NAME "mini"

MODULE_AUTHOR("JARA");
MODULE_LICENSE("GPL");

struct dentry *mini_debugfs_dir;
static int major;
static struct class *cls;
static struct file_operations mini_chardev_ops;

static long mini_vm_ioctl(struct file *flip,
            unsigned int ioctl, unsigned long arg)
{
    struct mini *mini = flip->private_data;

    mini_info("mini_vm_ioctl\n");

    switch(ioctl) {
    case MINI_ALLOC:
        break;
    case MINI_ENTER:
        mini_arch_enter(mini);
        csr_write(CSR_HSTATUS, csr_read(CSR_HSTATUS) | HSTATUS_HU);
        mini_info("0x%x\n", csr_read(CSR_HSTATUS));

        /*
        unsigned long val, guest_addr;
        guest_addr = 0x80000000;
        mini_info("val : 0x%lx\n", val);
        asm volatile(HLV_W(%[val], %[addr]) :[val] "=&r" (val): [addr] "r" (guest_addr) );
        mini_info("val : 0x%lx\n", val);
        */

        break;
    case MINI_EXIT:
        csr_write(CSR_HSTATUS, csr_read(CSR_HSTATUS) & !HSTATUS_HU);
        mini_info("0x%x\n", csr_read(CSR_HSTATUS));
        break;
    }
    return 0;
}

void mini_exit(void)
{
    debugfs_remove_recursive(mini_debugfs_dir);
}

static struct mini *mini_create_vm(unsigned long type, const char *fdname)
{
    struct mini *mini = mini_arch_alloc_vm();
    struct mini_memslots *slots;
    int r = -ENOMEM;
    int i, j;

    if(!mini)
        return ERR_PTR(-ENOMEM);

    mini_info("mini_create_vm\n");

    __module_get(mini_chardev_ops.owner);

	snprintf(mini->stats_id, sizeof(mini->stats_id), "mini-%d",
		 task_pid_nr(current));

	for (i = 0; i < MINI_ADDRESS_SPACE_NUM; i++) {
		for (j = 0; j < 2; j++) {
            slots = &mini->__memslots[i][j];

			atomic_long_set(&slots->last_used_slot, (unsigned long)NULL);
            slots->hva_tree = RB_ROOT_CACHED;
            slots->gfn_tree = RB_ROOT;
            hash_init(slots->id_hash);
            slots->node_idx = j;

            slots->generation = i;
        }
    }

    r = mini_arch_init_vm(mini, type);

    return mini;
}

static const struct file_operations mini_vm_fops = {
    .unlocked_ioctl = mini_vm_ioctl,
	.llseek		= noop_llseek,
};

static int mini_dev_ioctl_create_vm(unsigned long type)
{
    char fdname[ITOA_MAX_LEN + 1];
    int r, fd;
    struct mini *mini;
    struct file *file;

    fd = get_unused_fd_flags(O_CLOEXEC);
    if(fd < 0)
        return fd;

    mini_info("mini_dev_ioctl_create_vm %d \n", fd);

    snprintf(fdname, sizeof(fdname), "%d", fd);

    mini = mini_create_vm(type, fdname);
    if(IS_ERR(mini)) {
        r = PTR_ERR(mini);
    }

    file = anon_inode_getfile("mini-vm", &mini_vm_fops, mini, O_RDWR);
    if(IS_ERR(file)) {
        r = PTR_ERR(file);
    }

    fd_install(fd, file);
    return fd;

}

static long mini_dev_ioctl(struct file *flip, 
            unsigned int ioctl, unsigned long arg)
{
    int r = -EINVAL;
    mini_info("mini_dev_ioctl, %x\n", ioctl);


    switch(ioctl) {
    case MINI_CREATE_VM: 
        r = mini_dev_ioctl_create_vm(arg);
        break;
    default:
        return 0;
    }

    return r;
}

static struct file_operations mini_chardev_ops = {
    .unlocked_ioctl = mini_dev_ioctl,
    .llseek = noop_llseek,
};


int mini_init(unsigned size, unsigned align, struct module *module)
{
    mini_info("mini_init\n");

    major = register_chrdev(0, DEVICE_NAME, &mini_chardev_ops);
    if(major < 0) {
        mini_info("Registering char device failed with %d\n", major);
        return major;
    }

    mini_info("Assigned major number : %d\n", major);

    cls = class_create(DEVICE_NAME);
    device_create(cls, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);

    mini_info("Device created on /dev/%s\n", DEVICE_NAME);

    return 0;
}
EXPORT_SYMBOL_GPL(mini_init);

