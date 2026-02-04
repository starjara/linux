/* Garden : Copying SafeBPF */

#include <linux/types.h>

static __always_inline void bpf_sandbox_set_memory(void *mem_ptr,
						   volatile uintptr_t kern_ctx,
						   volatile uintptr_t or_mask,
						   volatile uintptr_t and_mask)
{

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
