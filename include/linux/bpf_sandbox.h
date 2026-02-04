/* Garden : Append Macro and Definition to Sandbox something */

#ifndef _BPF_SANDBOX_H
#define _BPF_SANDBOX_H

#include <linux/types.h>
#include <asm/bpf_sandbox.h>
#include <linux/smp.h>

#define BPF_SANDBOX_SIZE 2048
#define BPF_SANDBOX_INFO_SIZE 2048
#define MAX_BPF_STACK 512
#define BPF_SANDBOX_OR_MASK_OFFSET -8
#define BPF_SANDBOX_AND_MASK_OFFSET -16
#define BPF_SANDBOX_ORIG_SP_OFFSET -24

#define MAX_SYNC_PAIRS 10

#define IS_SANDBOX_ENABLED(type) ((type) == BPF_PROG_TYPE_XDP || (type) == BPF_PROG_TYPE_SOCKET_FILTER || (type) == BPF_PROG_TYPE_KPROBE)

#define current_sandbox (&sandboxes[smp_processor_id()])

#define current_sandbox_info (&current_sandbox->info)

#define current_sandbox_mem ((void *)&current_sandbox->mem)

struct bpf_sandbox_info {
        u64     prog_brk;
        u64     stack_end;
        u64     free_size;
        struct {
                void *sandbox_ptr;
                void *kernel_ptr;
        } sync_pairs[MAX_SYNC_PAIRS];
	u64 	or_mask;
	u64	kern_ctx;
};


struct bpf_sandbox_mem{
        u8 raw_info[BPF_SANDBOX_INFO_SIZE];
	u8 private[BPF_SANDBOX_SIZE];
};

union bpf_sandbox {
        struct bpf_sandbox_info info;
        struct bpf_sandbox_mem mem;
};

extern union bpf_sandbox *sandboxes;
extern void *sandbox_ctx;
extern size_t bpf_ctx_size_map[];
extern uintptr_t bpf_sandbox_and_mask;

static void bpf_sandbox_init_meminfo(struct bpf_sandbox_info *sandbox_info, size_t ctx_size)
{
	pr_info("[bpf_sandbox.h] Entering bpf_sandbox_init_meminfo\n");
	sandbox_info->prog_brk = (uintptr_t)sandbox_info + BPF_SANDBOX_INFO_SIZE + ctx_size;
	sandbox_info->stack_end = (uintptr_t)sandbox_info + BPF_SANDBOX_INFO_SIZE + BPF_SANDBOX_SIZE - MAX_BPF_STACK;
	sandbox_info->free_size = sandbox_info->stack_end - sandbox_info -> prog_brk;
	for (int i = 0; i < MAX_SYNC_PAIRS; i++){
		sandbox_info->sync_pairs[i].sandbox_ptr = 0;
		sandbox_info->sync_pairs[i].kernel_ptr = 0;
	}
}

static __always_inline void *sandbox_alloc(const struct bpf_prog *prog, const void *kernel_ctx)
{
	pr_info("[bpf_sandbox.h] Allocating Sandbox\n");
	size_t ctx_size = 0;

	if (!prog) {
		pr_err("Error: bpf_prog is NULL!\n");
		return NULL;
	}
	if(!bpf_ctx_size_map){
		pr_err("Error: bpf_ctx_size_map is NULL!\n");
		return NULL;
	}

	if (kernel_ctx){
		if(!current_sandbox_mem){
			pr_info("[bpf_sandbox.h] Current Sandbox Memory is NULL.\n");
		}
		else{
		ctx_size = bpf_ctx_size_map[prog->type];
		current_sandbox_info->kern_ctx = (u64)kernel_ctx;

		bpf_sandbox_init_meminfo(current_sandbox_info, ctx_size);
		memcpy(current_sandbox_mem, kernel_ctx, ctx_size);
		}
	} else {
		bpf_sandbox_init_meminfo(current_sandbox_info, 0);
	}

	sandbox_ctx = current_sandbox_mem;

	bpf_sandbox_set_memory(current_sandbox_mem, current_sandbox_info->kern_ctx, current_sandbox_info->or_mask, bpf_sandbox_and_mask);
	return current_sandbox_mem;
}

static __always_inline void sandbox_free(const struct bpf_prog *prog)
{
//	bpf_sync_kernel_ctx(prog, (void *)current_sandbox_info->kern_ctx, current_sandbox_mem);
	sandbox_ctx = NULL;
}

#endif
