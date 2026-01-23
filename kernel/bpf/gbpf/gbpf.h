#ifndef __GBPF_H__
#define __GBPF_H__

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/static_call.h>
#include <linux/bpf.h>

#include "gbpf_mmu.h"

#define GBPF_PAGE_SIZE 4096
#define GBPF_CONTEXT_SIZE 512
#define GBPF_STACK_SIZE (GBPF_PAGE_SIZE - GBPF_CONTEXT_SIZE)

#define gbpf_err(fmt, ...) \
    pr_err("[gBPF] [%i]: " fmt, task_pid_nr(current), ## __VA_ARGS__)
#define gbpf_info(fmt, ...) \
    pr_info("[gBPF] [%i]: " fmt, task_pid_nr(current), ## __VA_ARGS__)

//DECLARE_STATIC_CALL(gbpf_alloc_gpgd, void (*)(struct bpf_prog *));

#endif //__GBPF_H__
   
/* Garden : Context Structure */
struct gbpf_context {
	u64 args[8];
	u64 ret_value;
	u32 prog_id;
} __attribute__((packed));

/* Garden : Add to store private data into 4KB area */
struct gbpf_exec_env {
	
	struct gbpf_context context;


	u8 reserved[512 - sizeof(struct gbpf_context)];


	u8 stack[3584];

} __attribute__((packed, aligned(4096)));

