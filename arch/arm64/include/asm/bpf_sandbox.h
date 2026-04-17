/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 University of British Columbia
 * Author: Priyansh Rathi <techiepriyansh@gmail.com>
 */

#ifndef _ASM_BPF_SANDBOX_H
#define _ASM_BPF_SANDBOX_H

#include <asm/mte.h>
#include <asm/memory.h>

static __always_inline void convert_bpf_ctx_to_kernel_ctx(volatile u64 *ctx_ptr)
{
	volatile u64 ctx = __untagged_addr(*ctx_ptr);

	asm volatile (
		"sub %[c], %[c], #0x20\n"
		"ldr %[c], [%[c]]\n"
		: [c] "+r" (ctx)
		:
		);

	*ctx_ptr = ctx;
}

static __always_inline u64 bpf_helper_get_prog_type(void)
{
	u64 prog_id;

	asm volatile ("mov %[p], x12" : [p] "=r" (prog_id) :);

	return prog_id;
}

static __always_inline u64 bpf_sandbox_get_trampoline_target(u64 *p)
{
	volatile u64 prog_id;
	volatile u64 call_target;

	asm volatile(
		"mov %[p], x12\n"
		"mov %[t], x11\n"
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
		"mov x0, %[a]\n"
		"mov x1, %[b]\n"
		"mov x2, %[c]\n"
		"mov x3, %[d]\n"
		"mov x4, %[e]\n"
		"str lr, [sp, #-16]!\n"
		"blr %[t]\n"
		"ldr lr, [sp], #16\n"
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
	volatile void *m = __untagged_addr(mem_ptr);

	asm volatile (
		// save and_mask and or_mask to the end of 'metadata' page
		"stp %[am], %[om], [%[p], #-0x10]\n"
		// save kern_ctx to the end of 'metadata' page
		"str %[c], [%[p], #-0x20]\n"
		:
		: [p] "r" (m), [om] "r" (or_mask), [am] "r" (and_mask), [c] "r" (kern_ctx));
}

static __always_inline void bpf_sandbox_set_sp(void *sandbox)
{
	asm volatile (
		// mov the new stack ptr to x3 (reg storing 4th argument)
		"mov x3, %[a]\n"
		"add x3, x3, 0x7f0\n"
		:
		: [a] "r" (sandbox));
}

#endif /* _ASM_BPF_SANDBOX_H */
