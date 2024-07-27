#include <linux/verse_host.h>
#include <linux/module.h>
#include <linux/device.h>

#include "verse_mm.h"

// UAPI
#include <linux/verse.h>

// #define LOG_E verse_info("[virt/verse-main.c] Enter: %s\n", __func__);
#define LOG_E

#define DEVICE_NAME "verse"

MODULE_AUTHOR("JARA");
MODULE_LICENSE("GPL");

// Global static variables
static int major;
static int current_index;
static struct class *cls;
static struct device *device;
static struct file_operations verse_chardev_ops;
static struct verse **verse_array;
static struct mutex hgatp_mutex;

// =====================================================
// Verse mmap, munmap, and mprotect
// =====================================================
static int verse_dev_ioctl_mmap(unsigned long arg)
{
  struct verse *verse;
  struct verse_memory_region verse_mem;
  void __user *argp = (void __user *) arg;
  unsigned long new_page;
  int r = -EINVAL;
  
  LOG_E

  if (current_index < 0) {
    verse_error("\t[verse] Need enter first\n");
    return r;
  }
  
  verse = verse_array[current_index];
  if (verse == NULL) {
    verse_error("\t[verse] Failed to get verse struct\n");
    return r;
  }

  if (copy_from_user(&verse_mem, argp, sizeof(verse_mem))) {
    verse_error("\t[verse] Falied to get the input args from user\n");
    return r;
  }

  if (verse_mem.userspace_addr <= 0) {
    r = verse_arch_gstage_map(verse, &verse_mem);
  }
  else {
    r = verse_arch_gstage_map_from_user(verse, &verse_mem);
  }

  return r;
}

static int verse_dev_ioctl_munmap(unsigned long arg)
{
  struct verse *verse;
  struct verse_memory_region verse_mem;
  void __user *argp = (void __user *) arg;
  int r = -EINVAL;

  LOG_E

  if (current_index < 0) {
    verse_error("\t[verse] Need enter first\n");
    return r;
  }

  verse = verse_array[current_index];
  if (verse == NULL) {
    verse_error("\t[verse] Failed to get the verse struct\n");
    return r;
  }

  if (copy_from_user(&verse_mem, argp, sizeof(verse_mem))) {
    verse_error("\t[verse] Failed to get the input args from user\n");
    return r;
  }

  r = verse_arch_gstage_unmap(verse, &verse_mem);

  return r;
}

static int verse_dev_ioctl_mprotect(unsigned long arg)
{
  struct verse *verse;
  struct verse_memory_region verse_mem;
  void __user *argp = (void __user *) arg;
  int r = -EINVAL;

  LOG_E
  
  if (current_index < 0) {
    verse_error("\t[verse] Need enter first\n");
    return r;
  }

  verse = verse_array[current_index];
  if (verse == NULL) {
    verse_error("\t[verse] Failed to get the verse struct\n");
    return r;
  }

  if (copy_from_user(&verse_mem, argp, sizeof(verse_mem))) {
    verse_error("\t[verse] Failed to get the input args from user\n");
    return r;
  }

  r = verse_arch_gstage_mprotect(verse, &verse_mem);
  
  return r;
}

// =====================================================
// Verse enter and exit
// =====================================================
static int verse_dev_ioctl_enter_vm(int index)
{
  struct verse *verse;

  LOG_E 
  
  if(verse_array[index] == NULL) {
    verse_error("\t[verse] %d th verse is not exist, need create first\n", index);
    return -EINVAL;
  }

  if(mutex_is_locked(&hgatp_mutex)) {
    verse_error("\t[verse] Already entered %d\n", current_index);
  }
  
  verse = verse_array[index];

  verse_arch_enter_vm(verse);

  csr_write(CSR_HSTATUS, csr_read(CSR_HSTATUS) | HSTATUS_HU);
    
  current_index = index;
    
  mutex_lock(&hgatp_mutex);

  return 0;
}

static int verse_dev_ioctl_exit_vm(bool isFast)
{
  LOG_E 

  if(current_index < 0) {
    verse_error("\t[verse] Not in the enter state\n");
    return -EINVAL;
  }

  csr_write(CSR_HSTATUS, csr_read(CSR_HSTATUS) & (~HSTATUS_HU));

  if(isFast != 1) {
    verse_arch_exit_vm();
  }
  
  current_index = -1;

  mutex_unlock(&hgatp_mutex);

  return 0;
}

// =====================================================
// Verse create and destroy
// =====================================================
// Create a new verse
static struct verse *verse_create_vm(void)
{
  struct verse *verse = verse_arch_alloc_vm();
  struct verse_memory_region stack_region;
  struct vm_area_struct *vma;
  int r;
  unsigned long stack_start = current->mm->start_stack;
  unsigned long stack_end = current->mm->brk;

  LOG_E

  if(verse == NULL) {
    verse_error("\t\t[verse] Failed memory allocate for the new verse\n");
    return NULL;
  }

  VERSE_MMU_LOCK_INIT(verse);

  r = verse_arch_init_vm(verse);
  if (r != 0) {
    verse_error("\t\t[verse] Failed to init the new verse\n");
    verse_arch_free_vm(verse);
    verse = NULL;
  }

  // Get stack region
  vma = vma_lookup(current->mm, current->mm->start_stack);
  verse_info("0x%lx, 0x%lx\n", vma->vm_start, vma->vm_end);

  // stack_region.guest_phys_addr = vma->vm_start (512*PAGE_SIZE);
  stack_region.guest_phys_addr = vma->vm_start;// (512*PAGE_SIZE);
  // stack_region.memory_size = (1024*PAGE_SIZE);
  stack_region.memory_size = vma->vm_end - vma->vm_start;
  stack_region.prot = 0x3;
  
  if(!verse_arch_gstage_map(verse, &stack_region)) {
    verse_error("\t\t[verse] stack_region allocation failed\n");
    verse_arch_free_vm(verse);
    r = NULL;
  }

  verse->start_stack = vma->vm_end;
  verse->stack_size = stack_region.memory_size;

  return verse;
}

static int verse_dev_ioctl_create_vm(int index)
{
  struct verse *new_verse;

  LOG_E
  
  if(verse_array[index] != NULL) {
    verse_error("\t[verse] The index %d th verse already exist\n");
    return -EINVAL;
  }

  new_verse = verse_create_vm();
  
  if(new_verse == NULL) {
    verse_error("\t[verse] Failed to create a new verse\n");
    return -EINVAL;
  }

  verse_array[index] = new_verse;

  return 0;
}

// Device destroy
static void verse_dev_ioctl_destroy_vm(int index)
{
  struct verse *target = verse_array[index];

  LOG_E

  if(target == NULL) {
    verse_error("\t[verse] Target %d is not existing\n", index);
    return ;
  }

  verse_arch_flush_shadow_all(target);
  
  verse_arch_destroy_vm(target);
  verse_arch_free_vm(target);

  verse_array[index] = NULL;
}


// ioctl syscall handler
static long verse_dev_ioctl(struct file *flip,
			    unsigned int ioctl, unsigned long arg)
{
  int r = 0;

  switch(ioctl) {
  case VERSE_CREATE: {
    // verse_info("[verse] VERSE_CREATE, id : %d\n", arg);
    r = verse_dev_ioctl_create_vm(arg);
    break;
  }
  case VERSE_DESTROY: {
    // verse_info("[verse] VERSE_DESTROY, id : %d\n", arg);
    verse_dev_ioctl_destroy_vm(arg);
    break;
  }
  case VERSE_ENTER: {
    // verse_info("[verse] VERSE_ENTER, id : %d\n", arg);
    r = verse_dev_ioctl_enter_vm(arg);
    break;
  }
  case VERSE_EXIT: {
    // verse_info("[verse] VERSE_EXIT, id : %d\n", arg);
    r = verse_dev_ioctl_exit_vm(arg);
    break;
  }
  case VERSE_MMAP: {
    // verse_info("[verse] VERSE_MMAP\n");
    r = verse_dev_ioctl_mmap(arg);
    break;
  }
  case VERSE_MUNMAP: {
    // verse_info("[verse] VERSE_MUNMAP\n");
    r = verse_dev_ioctl_munmap(arg);
    break;
  }
  case VERSE_MPROTECT: {
    // verse_info("[verse] VERSE_MPROTECT\n");
    r = verse_dev_ioctl_mprotect(arg);
    break;
  }
  }
  
  return r;
}

static struct file_operations verse_chardev_ops = {
  .unlocked_ioctl = verse_dev_ioctl,
  .llseek = noop_llseek,
};

// Module init and exit
int verse_init(int length, struct module *module)
{
   verse_info("[verse] verse_init\n");

  verse_array = kzalloc(sizeof(struct verse *) * length, GFP_KERNEL);
  if(verse_array == NULL) {
    verse_error("[verse] verse array creation failed\n");
    return -1;
  }
  
  major = register_chrdev(0, DEVICE_NAME, &verse_chardev_ops);
  if (major < 0) {
    verse_error("Registering char device failed with %d\n", major);
    return major;
  }

  verse_info("[verse] Assigned major number : %d\n", major);

  cls = class_create(DEVICE_NAME);
  device = device_create(cls, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);

  current_index = -1;

  mutex_init(&hgatp_mutex);

  return 0;
}
EXPORT_SYMBOL_GPL(verse_init);

void verse_exit(void)
{
  verse_info("[verse] verse_exit\n");
  kvfree(verse_array);
  device_destroy(cls, MKDEV(major, 0));
  class_destroy(cls);
  unregister_chrdev(major, DEVICE_NAME); 
  return ;
}
EXPORT_SYMBOL_GPL(verse_exit);
