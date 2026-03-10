/* Garden : Append Macro and Definition to Sandbox something */

#ifndef _BPF_SANDBOX_H
#define _BPF_SANDBOX_H

#include <linux/bpf.h>
#include <linux/types.h>
#include <asm/bpf_sandbox.h>
#include <linux/smp.h>
#include <linux/hashtable.h>
#include <linux/bpf_ctx.h>

#define BPF_SANDBOX_SIZE 4096
#define BPF_SANDBOX_INFO_SIZE 4096 
#define MAX_BPF_STACK 512
#define BPF_SANDBOX_MAP_OR_MASK_OFFSET -40
#define BPF_SANDBOX_MAP_AND_MASK_OFFSET -48


#define BPF_SANDBOX_OR_MASK_OFFSET -8
#define BPF_SANDBOX_AND_MASK_OFFSET -16
#define BPF_SANDBOX_ORIG_SP_OFFSET -24

#define MAX_SYNC_PAIRS 10

#define IS_SANDBOX_ENABLED(type) ((type) == BPF_PROG_TYPE_XDP || (type) == BPF_PROG_TYPE_SOCKET_FILTER || (type) == BPF_PROG_TYPE_KPROBE || (type) == BPF_PROG_TYPE_PERF_EVENT)

#define current_sandbox (&sandboxes[smp_processor_id()])

#define current_sandbox_info (&current_sandbox->info)

#define current_sandbox_mem ((void *)&current_sandbox->mem.private)


void bpf_sandbox_add_map(struct bpf_map *map);

void record_map_ops(u64 prog_id, const struct bpf_map_ops *ops);


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



u64 sandbox_tramp(void);
extern void bpf_sync_kernel_ctx(const struct bpf_prog *prog, const void *kernel_ctx, void *bpf_ctx);
extern void init_sandbox_env(void *env);
__always_inline bool is_skb_helper(u64 prog_id, u64 fn); 

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
extern uintptr_t bpf_sandbox_or_masks[];


static __always_inline int msb(int b)
{
	int p = 0;
	b = b / 2;
	while (b != 0) {
		b = b / 2;
		p++;
	}
	return p;
}

static __always_inline uintptr_t gen_or_mask(volatile void *p, size_t s)
{
	uintptr_t m =(((uintptr_t)1 << (msb(s) + 1)) - 1) -s ;
	
	return (uintptr_t)p & ~m;
}

static __always_inline uintptr_t gen_and_mask(size_t s)
{
	uintptr_t m = (((uintptr_t)1 << (msb(s) + 1 )) - 1) - s;

	return (uintptr_t)m;
}

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
	int cpu = raw_smp_processor_id();
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

	bpf_sandbox_set_memory(current_sandbox_mem, current_sandbox_info->kern_ctx, bpf_sandbox_or_masks[cpu], bpf_sandbox_and_mask);
	return current_sandbox_mem;
}

static __always_inline void sandbox_free(const struct bpf_prog *prog)
{
	bpf_sync_kernel_ctx(prog, (void *)current_sandbox_info->kern_ctx, current_sandbox_mem);
}

#endif
