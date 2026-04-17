/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 University of British Columbia
 *
 * Author: Soo Yee Lim <sooyee@cs.ubc.ca>
 *
 */

#ifndef _BPF_SANDBOX_H
#define _BPF_SANDBOX_H

#include <linux/bpf.h>
#include <linux/bpf_ctx.h>
#include <linux/bpf_mte.h>
#include <linux/hashtable.h>
#include <asm/bpf_sandbox.h>

#ifdef CONFIG_BPF_SANDBOX

#define BPF_SANDBOX_SIZE (PAGE_SIZE / 2)
#define BPF_SANDBOX_INFO_SIZE (PAGE_SIZE / 2)
#define BPF_SANDBOX_TOTAL_SIZE sizeof(union bpf_sandbox)
// mask offset from the top of private memory (i.e., at the end of the 'metadata' page)
#define BPF_SANDBOX_OR_MASK_OFFSET -8
#define BPF_SANDBOX_AND_MASK_OFFSET -16
// orginal rsp offset from the top of private memory (i.e., at the end of 'metadata' page)
#define BPF_SANDBOX_ORIG_RSP_OFFSET -24
// orginal ctx offset from the top of private memory (i.e., at the end of 'metadata' page)
#define BPF_SANDBOX_KERN_CTX_OFFSET -32
// map masks offset from the top of private memory (i.e., at the end of 'metadata' page)
#define BPF_SANDBOX_MAP_OR_MASK_OFFSET -40
#define BPF_SANDBOX_MAP_AND_MASK_OFFSET -48
// offsets from sandbox base pointer (%rbp), used by the JIT compiler to emit code
#define OR_MASK_OFFSET_FROM_RBP  ((u32)BPF_SANDBOX_OR_MASK_OFFSET - (BPF_SANDBOX_SIZE - 1))
#define AND_MASK_OFFSET_FROM_RBP  ((u32)BPF_SANDBOX_AND_MASK_OFFSET - (BPF_SANDBOX_SIZE - 1))
#define ORIG_RSP_OFFSET_FROM_RBP  ((u32)BPF_SANDBOX_ORIG_RSP_OFFSET - (BPF_SANDBOX_SIZE - 1))
#define MAP_OR_MASK_OFFSET_FROM_RBP  ((u32)BPF_SANDBOX_MAP_OR_MASK_OFFSET - (BPF_SANDBOX_SIZE - 1))
#define MAP_AND_MASK_OFFSET_FROM_RBP  ((u32)BPF_SANDBOX_MAP_AND_MASK_OFFSET - \
									   (BPF_SANDBOX_SIZE - 1))
#define MAX_SYNC_PAIRS 10

// Reserve 16 bytes in the stack for storing counters
#define RESERVE_TWO     16
// Counter offset in the stack
#define MEMCOUNT_OFFSET         8
#define TRAMPCOUNT_OFFSET       16

#define current_sandbox (&sandboxes[smp_processor_id()])
#define current_sandbox_info (&current_sandbox->info)
#ifdef CONFIG_BPF_SANDBOX_MTE
#define current_sandbox_mem ((void *)bpf_mte_set_tag(current_sandbox->mem.private, \
							BPF_MTE_TAG_SANDBOX))
#else
#define current_sandbox_mem  ((void *)current_sandbox->mem.private)
#endif /* CONFIG_BPF_SANDBOX_MTE */

#define IS_SANDBOX_ENABLED(type) ( \
		type == BPF_PROG_TYPE_SOCKET_FILTER \
		|| type == BPF_PROG_TYPE_XDP \
		|| type == BPF_PROG_TYPE_KPROBE \
		)

/**
 * struct bpf_sandbox_sync - stores memory addresses to enable synchronization between
 * sandbox and kernel
 *
 * @sandbox_ptr: pointer to sandbox memory address
 * @kernel_ptr: pointer to kernel memory address
 */
struct bpf_sandbox_sync {
	u64	sandbox_ptr;
	u64	kernel_ptr;
};

/**
 * struct bpf_sandbox_info - stores bpf sandbox environment information
 *
 * @prog_brk: end of the data segment
 * @stack_end: end address of the stack in private memory
 * @free_size: amount of unallocated memory available
 * @sync_pairs: holds bpf_sandbox_sync elements
 * @or_mask: or_mask unique to the sandbox
 */
struct bpf_sandbox_info {
	/* Dynamic allocation metadata */
	u64			prog_brk;
	u64			stack_end;
	u64			free_size;
	struct bpf_sandbox_sync sync_pairs[MAX_SYNC_PAIRS];
	/* Address Mask */
	u64			or_mask;
	/* Original Kernel Ctx */
	u64			kern_ctx;
};

/**
 * struct bpf_sandbox_mem - components of sandbox memory
 *
 * @raw_info: array for storing sandbox info
 * @private: array for private sandbox memory
 */
struct bpf_sandbox_mem {
	u8 raw_info[BPF_SANDBOX_INFO_SIZE];
	u8 private[BPF_SANDBOX_SIZE];
};

/**
 * union bpf_sandbox - field that points to either sandbox info or memory
 *
 * @info: stores bpf sandbox environment information
 * @mem: sandbox raw info and private memory
 */
union bpf_sandbox {
	struct bpf_sandbox_info info;
	struct bpf_sandbox_mem	mem;
};

extern size_t bpf_ctx_size_map[]; //TODO: can be removed
extern uintptr_t bpf_sandbox_and_mask;
extern union bpf_sandbox *sandboxes;
extern void *sandbox_ctx;

/**
 * init_sandbox_env() - initializes sandbox environments
 *
 * @verifier_env: bpf verification environment
 */
void init_sandbox_env(void *verifier_env);

/**
 * sandbox_tramp() - checks validity of helper function before calling
 */
#if defined(CONFIG_X86_64)
u64 sandbox_tramp(void);
#elif defined(CONFIG_ARM64)
void sandbox_tramp(volatile u64 r1, volatile u64 r2, volatile u64 r3, volatile u64 r4,
		volatile u64 r5);
#elif defined(CONFIG_ARCH_RV64I)
void sandbox_tramp(volatile u64 r1, volatile u64 r2, volatile u64 r3, volatile u64 r4,
		volatile u64 r5);
#endif

/**
 * record_map_ops() - Keeps track of valid map operations (for CFI)
 */
void record_map_ops(u64 prog_id, const struct bpf_map_ops *ops);
void record_jit_helper_target(u64 prog_id, u64 fn);

/**
 * msb() - gets the position of the most significant set bit
 *
 * @b: size of memory allocated in number of bytes
 *
 * Return: the position of the msb starting from 0
 */
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

/**
 * gen_or_mask() - calculates an OR mask based on pointer p and size s
 *
 * @p: void pointer
 * @s: size in number of bytes
 *
 * Return: Returns an address aligned to the boundary provided by s
 */
static __always_inline uintptr_t gen_or_mask(volatile void *p, size_t s)
{
	uintptr_t m = (((uintptr_t)1 << (msb(s) + 1)) - 1) - s;

	return (uintptr_t)p & ~m;
}

/**
 * gen_and_mask() - calculates an AND mask based on size s
 *
 * @s: size in number of bytes
 *
 * Return: Returns an address where the highest bit is set to the msb and
 * there are 's' trailing zeros
 */
static __always_inline uintptr_t gen_and_mask(size_t s)
{
	uintptr_t m = (((uintptr_t)1 << (msb(s) + 1)) - 1) - s;

	return (uintptr_t)m;
}

/**
 * is_caller_sandboxed() - checks if the caller is sandboxed
 *                         (called within helper functions)
 *
 * Return: Returns true if the caller eBPF program is sandboxed,
 *         false otherwise
 */
static __always_inline bool is_caller_sandboxed(void)
{
#if defined(CONFIG_BPF_SFI_TRAMPOLINE) || defined(CONFIG_BPF_SANDBOX_MEMORY_MANAGEMENT)
	u8 prog_id;

#if defined(CONFIG_X86_64) || defined(CONFIG_ARM64) || defined(CONFIG_ARCH_RV64I)
	prog_id = bpf_helper_get_prog_type();
	return IS_SANDBOX_ENABLED(prog_id);
#else
	panic("BPF Sandbox: Architecture not supported");
#endif         /* CONFIG_X86_64 or CONFIG_ARM64 */

	return false;
#else /* CONFIG_BPF_SFI_TRAMPOLINE or CONFIG_BPF_SANDBOX_MEMORY_MANAGEMENT */
	return false;
#endif /* CONFIG_BPF_SFI_TRAMPOLINE or CONFIG_BPF_SANDBOX_MEMORY_MANAGEMENT */
}

#ifdef CONFIG_BPF_SANDBOX_MEMORY_MANAGEMENT
/**
 * bpf_sandbox_init_meminfo() - initializes bpf sandbox information for a given bpf program type
 *
 * @sandbox_info: struct containing bpf sandbox environment information
 * @ctx_size: context size of given bpf program type
 */
static void bpf_sandbox_init_meminfo(struct bpf_sandbox_info *sandbox_info, size_t ctx_size)
{
	sandbox_info->prog_brk = (uintptr_t)sandbox_info + BPF_SANDBOX_INFO_SIZE + ctx_size;
	sandbox_info->stack_end = (uintptr_t)sandbox_info + BPF_SANDBOX_INFO_SIZE
				  + BPF_SANDBOX_SIZE - MAX_BPF_STACK;
	sandbox_info->free_size = sandbox_info->stack_end - sandbox_info->prog_brk;
	for (int i = 0; i < MAX_SYNC_PAIRS; i++) {
		sandbox_info->sync_pairs[i].sandbox_ptr = 0;
		sandbox_info->sync_pairs[i].kernel_ptr = 0;
	}
}

/**
 * sandbox_alloc() - memory is allocated for a bpf sandbox based on program type and context
 *
 * @prog: bpf program pointer
 * @kernel_ctx: actual kernel context
 *
 * If the context pointer is not null, the context size is obtained. Then the
 * memory information for the specific bpf sandbox is initialized. Next, the
 * data in context pointer is copied to the current sandbox memory, and the
 * bpf sandbox memory is configured with the obtained context information.
 *
 * If the context pointer is null, the memory information for the specific bpf
 * sandbox is initialized, and the bpf sandbox memory is configured without
 * prexisting context information.
 *
 * Return: the pointer to the memory address of the allocated sandbox memory
 */
static __always_inline void *sandbox_alloc(const struct bpf_prog *prog, const void *kernel_ctx)
{
	size_t ctx_size;

	pr_info("Sandbox allocation\n");

	if (kernel_ctx) {
		ctx_size = bpf_ctx_size_map[prog->type]; // TODO: change this to bpf ctx size
		current_sandbox_info->kern_ctx = (u64)kernel_ctx;
		bpf_sandbox_init_meminfo(current_sandbox_info, ctx_size);
#ifdef CONFIG_BPF_SANDBOX_CTX
		if (IS_SANDBOX_CTX_SUPPORTED(prog->type))
			bpf_create_prog_ctx(prog, kernel_ctx, current_sandbox_mem);
		else
			memcpy(current_sandbox_mem, kernel_ctx, ctx_size);
#else
		memcpy(current_sandbox_mem, kernel_ctx, ctx_size);
#endif /* CONFIG_BPF_SANDBOX_CTX */
	} else {
		bpf_sandbox_init_meminfo(current_sandbox_info, 0);
	}

	sandbox_ctx = current_sandbox_mem;
	bpf_sandbox_set_memory(current_sandbox_mem, current_sandbox_info->kern_ctx,
			       current_sandbox_info->or_mask, bpf_sandbox_and_mask);

	return current_sandbox_mem;
}

/**
 * sandbox_free() - Performs ctx syncing and (supposedly sandbox cleanup) upon exit
 *
 * @prog: bpf program pointer
 */
static __always_inline void sandbox_free(const struct bpf_prog *prog)
{
  pr_info("Sandbox free\n");
#ifdef CONFIG_BPF_SANDBOX_CTX
	bpf_sync_kernel_ctx(prog, (void *)current_sandbox_info->kern_ctx, current_sandbox_mem);
#endif /* CONFIG_BPF_SANDBOX_CTX */
}
#endif /* CONFIG_BPF_SANDBOX_MEMORY_MANAGEMENT */

#ifdef CONFIG_BPF_SANDBOX_STACK_MANAGEMENT
/**
 * min_sandbox_alloc() - memory is allocated for a bpf stack
 *
 * @prog: bpf program pointer
 * @kernel_ctx: actual kernel context
 *
 * If the context exists, the kernel object size is obtained.
 * We tag the kernel object, including the nested structures being accessed.
 *
 * Return: the tagged ctx pointer
 */
#ifdef CONFIG_BPF_SANDBOX_MTE_TAG_CTX
static __always_inline void *min_sandbox_alloc(const struct bpf_prog *prog, const void *ctx)
{
	size_t ctx_size = bpf_ctx_size_map[prog->type];

	bpf_mte_tag_ctx(prog, ctx, ctx_size, BPF_MTE_TAG_SANDBOX, false);
	bpf_sandbox_set_sp(current_sandbox_mem);
	return bpf_mte_set_tag(ctx, BPF_MTE_TAG_SANDBOX);
}
#endif /* CONFIG_BPF_SANDBOX_MTE_TAG_CTX */

#ifndef CONFIG_BPF_SANDBOX_MTE_TAG_CTX
static __always_inline void *min_sandbox_alloc(const struct bpf_prog *prog, const void *ctx)
{
	bpf_sandbox_set_sp(current_sandbox_mem);
	return (void *)ctx;
}
#endif /* CONFIG_BPF_SANDBOX_MTE_TAG_CTX */

/**
 * min_sandbox_free() - Untag ctx upon exit
 *
 * @prog: bpf program pointer
 */
static __always_inline void min_sandbox_free(const struct bpf_prog *prog, const void *ctx)
{
#ifdef CONFIG_BPF_SANDBOX_MTE_TAG_CTX
	size_t ctx_size = bpf_ctx_size_map[prog->type];

	bpf_mte_tag_ctx(prog, ctx, ctx_size, BPF_MTE_TAG_KERNEL, false);
#endif /* CONFIG_BPF_SANDBOX_MTE_TAG_CTX */
}
#endif /* CONFIG_BPF_SANDBOX_STACK_MANAGEMENT */

#endif  /* CONFIG_BPF_SANDBOX */
#endif  /* _BPF_SANDBOX_H */
