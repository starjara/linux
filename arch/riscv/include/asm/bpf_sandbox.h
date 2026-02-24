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
    register u64 a6_reg asm("a6");
    register u64 a7_reg asm("a7");

    if (p) *p = a6_reg;

    return a7_reg;
}

/*
static __always_inline u64 bpf_sandbox_call_trampoline_target(volatile u64 call_target,
                volatile u64 r1, volatile u64 r2, volatile u64 r3,
                volatile u64 r4, volatile u64 r5)
{
    volatile u64 ret;

    asm volatile (
        "mv a0, a5\n\t"
        "mv a1, %[b]\n\t"
        "mv a2, %[c]\n\t"
        "mv a3, %[d]\n\t"
        "mv a4, %[e]\n\t"
        "jalr ra, %[t], 0\n\t"
        "mv %0, a0\n\t"
        : [ret] "=r" (ret)
        : [t] "r" (call_target), [a] "r" (r1), [b] "r" (r2),
          [c] "r" (r3), [d] "r" (r4), [e] "r" (r5)
        : "a0", "a1", "a2", "a3", "a4", "ra"
    );

    return ret;
}
*/


/* arch/riscv/include/asm/bpf_sandbox.h (또는 적절한 위치) */

static __always_inline u64 bpf_sandbox_call_trampoline_target(u64 target, u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
    // 컴파일러에게 이 변수들은 반드시 지정된 레지스터에만 두라고 강제합니다.
    register u64 a0_reg asm("a0") = r1; 
    register u64 a1_reg asm("a1") = r2;
    register u64 a2_reg asm("a2") = r3;
    register u64 a3_reg asm("a3") = r4;
    register u64 a4_reg asm("a4") = r5;
    register u64 t1_reg asm("t1") = target;
    u64 ret;

    asm volatile (
        "jalr ra, %1\n\t"  // t1(target) 주소로 점프
        "mv %0, a0\n\t"    // 결과값(a0)을 ret에 저장
        : "=r" (ret)
        : "r" (t1_reg), "r" (a0_reg), "r" (a1_reg), "r" (a2_reg), "r" (a3_reg), "r" (a4_reg)
        : "ra", "memory"
    );
    return ret;
}

static __always_inline void convert_bpf_ctx_to_kernel_ctx(volatile u64 *ctx_ptr)
{

    *ctx_ptr = *ctx_ptr + 16;
}
