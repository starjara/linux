#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/debugfs.h>

#include <linux/hugetlb.h>

#include <linux/anon_inodes.h>

#include <linux/mm.h>

#include "gbpf.h"

#define DEVICE_NAME "gbpf"

struct dentry *gbpf_debugfs_dir;
static int major;
static struct class *cls;
static struct file_operations domv_chardev_ops;

// Module init
static int __init gbpf_module_init(void) {
  gbpf_info("[gBPF] gBPF module loaded\n");

  major = register_chrdev(0, DEVICE_NAME, &domv_chardev_ops);
  
  if(major < 0) {
    gbpf_info("Registering char device failed with %d\n", major);
    return major;
  }

  gbpf_info("[gBPF] Assigned major number : %d\n", major);

  cls = class_create(DEVICE_NAME);
  device_create(cls, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);

  return 0;
}

// Module exit
static void __exit gbpf_module_exit(void) {
  debugfs_remove_recursive(gbpf_debugfs_dir);

  device_destroy(cls, MKDEV(major, 0));
  class_destroy(cls);
  unregister_chrdev(major, DEVICE_NAME);
  
  gbpf_info("gBPF module removed\n");
}

// Registering init and exit function
module_init(gbpf_module_init);
module_exit(gbpf_module_exit);

// Module description
MODULE_LICENSE("GPL");
MODULE_AUTHOR("JARA");
MODULE_DESCRIPTION("gBPF Module");


