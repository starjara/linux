/* Garden : Copying SafeBPF */

#include <linux/types.h>
static __always_inline void bpf_sandbox_set_memory(void *mem_ptr,
						   volatile uintptr_t kern_ctx,
						   volatile uintptr_t or_mask,
						   volatile uintptr_t and_mask)
{

	pr_info("[Garden] Setting Memory: or_mask=0x%lx, and_mask=0x%lx\n", or_mask, and_mask);
	__asm__ __volatile__ (
		"sd %[am], -16(%[p])\n\t"
		"sd %[om], -8(%[p])\n\t"
		"sd %[c], -32(%[p])\n\t"
		:
		: [p] "r" (mem_ptr),
		  [om] "r" (or_mask),
		  [am] "r" (and_mask),
		  [c] "r" (kern_ctx)
		: "memory"
	);
}


static __always_inline u64 bpf_sandbox_get_trampoline_target(u64 *p)
{
    volatile u64 prog_id;
    volatile u64 call_target;

    asm volatile (
		    "addi sp, sp, -64\n\t"
		    "sd a0, 0(sp)\n\t"
		    "sd a1, 8(sp)\n\t"
		    "sd a2, 16(sp)\n\t"
		    "sd a3, 24(sp)\n\t"
		    "sd a4, 32(sp)\n\t"
		    "sd ra, 40(sp)\n\t"
		    "sd t2, 48(sp)\n\t"
		    "mv %0, a6\n\t"
		    "mv %1, a7\n\t"
		    : "=r" (prog_id), "=r" (call_target)
		    :
		    : "memory"
		 );

    *p = prog_id;
    return call_target;
}

static __always_inline u64 bpf_sandbox_call_trampoline_target(volatile u64 call_target)
{
	volatile u64 ret_val;

	asm volatile (
		"ld a0, 0(sp)\n\t"
		"ld a1, 8(sp)\n\t"
		"ld a2, 16(sp)\n\t"
		"ld a3, 24(sp)\n\t"
		"ld a4, 32(sp)\n\t"
		"ld ra, 40(sp)\n\t"
		"ld a5, 48(sp)\n\t"
		"addi sp, sp, 64\n\t"

		"jalr ra, %1\n\t"
		"mv %0, a0\n\t"
		: "=r" (ret_val)
		: "r" (call_target)
		: "a0", "a1", "a2", "a3", "a4", "ra", "memory"
	);

	return ret_val;
}


static __always_inline void convert_bpf_ctx_to_kernel_ctx(void)
{
	
	asm volatile ( 
		"ld t0, 0(sp)\n\t"
		"ld t0, -32(t0)\n\t"
		"sd t0, 0(sp)\n\t"
		:
		:
		: "t0", "memory"
	);

}
