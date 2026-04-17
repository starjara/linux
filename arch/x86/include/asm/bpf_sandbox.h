/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 University of British Columbia
 * Author: Soo Yee Lim <sooyee@cs.ubc.ca>
 */

#ifndef _ASM_BPF_SANDBOX_H
#define _ASM_BPF_SANDBOX_H

/**
 * convert_bpf_ctx_to_kernel_ctx() - change the bpf ctx to the
 *									 kernel ctx (for helpers)
 */
static __always_inline void convert_bpf_ctx_to_kernel_ctx(void)
{
	__asm__ __volatile__ (
		"pop %%rdi\n\t"
		"mov -0x20(%%rdi), %%rdi\n\t"
		"push %%rdi\n\t"
		:
		:
		);
}

/**
 * bpf_helper_get_prog_type() - gets the program type ID
 *
 * Return: program type ID
 */
static __always_inline u64 bpf_helper_get_prog_type(void)
{
	u64 prog_id;

	__asm__ __volatile__ (
		"mov %%r9, %[p]\n\t"
		: [p] "=r" (prog_id)
		:
		);

	return prog_id;
}

/**
 * bpf_sandbox_get_trampoline_target() - gets the call target address from r9 register
 *
 * @p: pointer for program type identifer
 *
 * Pushes the registers values to the stack and saves the values of the program
 * type identifer and helper function address into the prog_id and call_target
 * variables, respectively, so that their values are acessible by the C code.
 *
 * Return: Returns a 64 bit unsigned integeter, call_target, which is the address
 * of the helper function.
 */
static __always_inline u64 bpf_sandbox_get_trampoline_target(u64 *p)
{
	volatile u64 prog_id;
	volatile u64 call_target;

	// Get the call target address
	__asm__ __volatile__ (
		"push %%r9\n\t"
		"push %%rsi\n\t"
		"push %%rdx\n\t"
		"push %%rcx\n\t"
		"push %%r8\n\t"
		"push %%rdi\n\t"
		"mov %%r9, %[p]\n\t"
		"mov %%r11, %[t]\n\t"
		: [p] "=r" (prog_id), [t] "=r" (call_target)
		:
		);
	*p = prog_id;

	return call_target;
}

/**
 * bpf_sandbox_call_trampoline_target() - calls the valid helper function
 *
 * @call_target: helper function address
 *
 * Removes the data from the stack, stores it in the respective registers, and
 * calls the helper function that is specified in the input list.
 */
static __always_inline u64 bpf_sandbox_call_trampoline_target(volatile u64 call_target)
{
	volatile u64 ret;

	// Call the valid helper function
	__asm__ __volatile__ (
		"pop %%rdi\n\t"
		"pop %%r8\n\t"
		"pop %%rcx\n\t"
		"pop %%rdx\n\t"
		"pop %%rsi\n\t"
		"pop %%r9\n\t"
		"call *%[t]\n\t"
		"mov %%rax, %[r]\n\t"
		: [r] "=r" (ret)
		: [t] "r" (call_target)
		);

	return ret;
}

// TODO: pass offset from filter.h, don't hardcode

/**
 * bpf_sandbox_set_memory() - configures bpf sandbox memory without context info
 *
 * @mem_ptr: pointer to memory allocated in the bpf sandbox cache
 * @kern_ctx: address of the original kernel ctx
 * @or_mask: OR opperation mask for address maskinng
 * @and_mask: OR opperation mask for address maskinng
 *
 * For the bpf program, this function ensures that the top of the private stack
 * is retained at the bottom of private memory, and the OR and AND masks
 * are sored in registers.
 */
static __always_inline void bpf_sandbox_set_memory(void *mem_ptr,
						   volatile uintptr_t	kern_ctx,
						   volatile uintptr_t	or_mask,
						   volatile uintptr_t	and_mask)
{
	volatile void *m = mem_ptr;

	__asm__ __volatile__ (
		// save or_mask to the end of 'metadata' page
		"mov %[om], -0x8(%[p])\n\t"
		// save and_mask to the end of 'metadata' page
		"mov %[am], -0x10(%[p])\n\t"
		// save kern_ctx to the end of 'metadata' page
		"mov %[c], -0x20(%[p])\n\t"
		: [p] "=r" (m)
		: [om] "r" (or_mask), [am] "r" (and_mask), [c] "r" (kern_ctx)
		);
}

/**
 * bpf_sandbox_retrieve_counter() - saves the masking and trampoline counts
 *
 * @mask: pointer to masking count
 * @tramp: pointer to trampoline count
 *
 * Retrieves the number of times masking and trampoline calls are made
 * during the execution of a specific bpf program in order to make
 * complexity evaluations.
 */
static __always_inline void bpf_sandbox_retrieve_counter(u64 *mask, u64 *tramp)
{
	volatile u64 masking_count = 0;
	volatile u64 trampoline_count = 0;

	__asm__ __volatile__ (
		"mov %%r8, %[m]\n\t"            // save the masking count
		"mov %%r9, %[t]\n\t"            // save the trampoline count
		: [m] "=r" (masking_count), [t] "=r" (trampoline_count)
		:
		);

	*mask = masking_count;
	*tramp = trampoline_count;
}

#endif /* _ASM_BPF_SANDBOX_H */
