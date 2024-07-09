#ifndef __VERSE_HOST_H__
#define __VERSE_HOST_H__

#include <linux/module.h>
#include <linux/mm.h>
#include <linux/slab.h>

#include <linux/verse.h>

// Arch dependent
#include <asm/verse_host.h>

#define verse_error(fmt, ...) \
  pr_err("verse [%i]: " fmt, task_pid_nr(current), ## __VA_ARGS__)
#define verse_info(fmt, ...) \
  pr_info("verse [%i]: " fmt, task_pid_nr(current), ## __VA_ARGS__)


// Data structures
struct verse {
  // MMU spin lock 
  spinlock_t mmu_lock;

  struct mm_struct *mm; // Userspace tied to this vm

  struct verse_arch arch;
  
};

// static functions
static inline struct verse *verse_arch_alloc_vm(void)
{
  return kzalloc(sizeof(struct verse), GFP_KERNEL_ACCOUNT);
}
static inline void verse_arch_free_vm(struct verse *verse)
{
  kvfree(verse);
}

// Functions
// Architecture dependent functions
void verse_arch_destroy_vm(struct verse *verse);
int verse_arch_init_vm(struct verse *verse);
void verse_arch_flush_shadow_all(struct verse *verse);
void verse_arch_enter_vm(struct verse *verse);
void verse_arch_exit_vm(void);
int verse_arch_gstage_map(struct verse *verse, struct verse_memory_region *verse_mem);
int verse_arch_gstage_unmap(struct verse *verse, struct verse_memory_region *verse_mem);
int verse_arch_gstage_mprotect(struct verse *verse, struct verse_memory_region *verse_mem);

// Module functions
// create and destroy
static struct verse *verse_create_vm(void);
static void verse_destroy_vm(struct verse *verse);

// IOCTL function
static long verse_dev_ioctl(struct file *flip, unsigned int ioctl, unsigned long arg);

// create and destroy
static int verse_dev_ioctl_create_vm(int index);
static void verse_dev_ioctl_destroy_vm(int index);

// enter and exit
static int verse_dev_ioctl_enter_vm(int index);
static int verse_dev_ioctl_exit_vm(bool isFast);

// mmap and munmap
static int verse_dev_ioctl_mmap(unsigned long arg);
static int verse_dev_ioctl_munmap(unsigned long arg);
static int verse_dev_ioctl_mprotect(unsigned long arg);


// Init and dest
int verse_init(int len, struct module *module);
void verse_exit(void);
  
#endif // __VERSE_HOST_H__
