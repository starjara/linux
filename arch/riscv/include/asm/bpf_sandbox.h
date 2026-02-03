/* Garden : Copying SafeBPF */

#include <linux/types.h>

/*
static __always_inline void bpf_sandbox_set_memory(void *mem_ptr, volatile uintptr_t kern_ctx, volatile uintptr_t or_mask, volatile uintptr_t and_mask)
{
	asm volatile (
		"sd %[om], -8(%[p])\n\t"
		"sd %[am], -16(%[p])\n\t"
		"sd %[c], -32(%[p])\n\t"

		:
		: [p]  "r" (mem_ptr),
		  [om] "r" (or_mask),
		  [am] "r" (and_mask),
		  [c]  "r" (kern_ctx)
		: "memory"
	);
}
*/

static __always_inline void bpf_sandbox_set_memory(void *mem_ptr,
                                                   volatile uintptr_t kern_ctx,
                                                   volatile uintptr_t or_mask,
                                                   volatile uintptr_t and_mask)
{
    if (!mem_ptr || (unsigned long)mem_ptr < 0x1000) {
        pr_err("[CRITICAL] bpf_sandbox_set_memory: Invalid mem_ptr detected! (%px)\n", mem_ptr);
        return;
    }

    pr_info("[DEBUG] bpf_sandbox_set_memory Start:\n");
    pr_info("  - Base Mem: %px\n", mem_ptr);
    pr_info("  - Writing at +0:  %lx (OR Mask)\n", (unsigned long)or_mask);
    pr_info("  - Writing at +8: %lx (AND Mask)\n", (unsigned long)and_mask);
    pr_info("  - Writing at +16: %lx (Kern Ctx)\n", (unsigned long)kern_ctx);

    asm volatile (
        "sd %[om], 16(%[p])\n\t"
	"sd %[am], 8(%[p])\n\t"
	"sd %[c], 0(%[p])\n\t"
        :
        : [p] "r" (mem_ptr),
          [om] "r" (or_mask),
          [am] "r" (and_mask),
          [c] "r" (kern_ctx)
        : "memory"
    );

    // pr_info("[DEBUG] bpf_sandbox_set_memory: Metadata Written Successfully.\n");
}
