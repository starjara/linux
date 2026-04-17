/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 University of British Columbia
 * Author: Priyansh Rathi <techiepriyansh@gmail.com>
 */

#ifndef _ASM_BPF_SANDBOX_H
#define _ASM_BPF_SANDBOX_H

//#include <asm/memory.h>

static __always_inline void convert_bpf_ctx_to_kernel_ctx(volatile u64 *ctx_ptr)
{
	volatile u64 ctx = (*ctx_ptr);

	asm volatile (
		"addi %[c], %[c], -32\n"
		"ld %[c], 0(%[c])\n"
		: [c] "+r" (ctx)
		:
		: "memory"
		);

	*ctx_ptr = ctx;
}

static __always_inline u64 bpf_helper_get_prog_type(void)
{
	u64 prog_id;

	asm volatile ("mv %[p], s10" : [p] "=r" (prog_id) :);

	return prog_id;
}

static __always_inline u64 bpf_sandbox_get_trampoline_target(u64 *p)
{
	volatile u64 prog_id;
	volatile u64 call_target;

	asm volatile(
		"mv %[p], s10\n"
		"mv %[t], s11\n"
		: [p] "=r" (prog_id), [t] "=r" (call_target)
		:
		);
	*p = prog_id;

	return call_target;
}

static __always_inline void bpf_sandbox_call_trampoline_target(volatile u64 call_target,
		volatile u64 r1, volatile u64 r2, volatile u64 r3, volatile u64 r4,
		volatile u64 r5)
{
	asm volatile (
		"mv a0, %[a]\n"
		"mv a1, %[b]\n"
		"mv a2, %[c]\n"
		"mv a3, %[d]\n"
		"mv a4, %[e]\n"

		"addi sp, sp, -16\n"
		"sd ra, 0(sp)\n"
		
		"jalr ra, 0(%[t])\n"

		"ld ra, 0(sp)\n"
		"addi sp, sp, 16\n"
		:
		: [t] "r" (call_target), [a] "r" (r1), [b] "r" (r2),
		  [c] "r" (r3), [d] "r" (r4), [e] "r" (r5)
		: "x0", "x1", "x2", "x3", "x4"
		);
}

static __always_inline void bpf_sandbox_set_memory(void *mem_ptr,
						   volatile uintptr_t	kern_ctx,
						   volatile uintptr_t	or_mask,
						   volatile uintptr_t	and_mask)
{
	volatile void *m = (mem_ptr);

	asm volatile (
		// save and_mask and or_mask to the end of 'metadata' page
	        "sd %[am], -16(%[p])\n"
		"sd %[om], -8(%[p])\n"
		// save kern_ctx to the end of 'metadata' page
		"sd %[c], -32(%[p])\n"
		:
		: [p] "r" (m), [om] "r" (or_mask), [am] "r" (and_mask), [c] "r" (kern_ctx));
}

static __always_inline void bpf_sandbox_set_sp(void *sandbox)
{
	asm volatile (
		// mov the new stack ptr to x3 (reg storing 4th argument)
		"mv a3, %[a]\n"
		"addi a3, a3, 0x7f0\n"
		:
		: [a] "r" (sandbox));
}

#endif /* _ASM_BPF_SANDBOX_H */
