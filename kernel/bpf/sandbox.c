/* Garden : Copying SafeBPF code */
#include <linux/cpu.h>
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/bpf_sandbox.h>
#include <linux/skmsg.h>
#include <linux/perf_event.h>
#include <linux/netfilter.h>
#include <net/netfilter/nf_bpf_link.h>
#include <linux/bpf_lsm.h>
#include <linux/btf_ids.h>
#include "disasm.h"


union bpf_sandbox *sandboxes;
void *sandbox_ctx;
uintptr_t bpf_sandbox_and_mask;
EXPORT_SYMBOL(bpf_sandbox_and_mask);

static __always_inline int msb(int b)
{
	int p = 0;

	b = b / 2;
	while (b != 0){
		b = b / 2;
		p++;
	}
	return p;
}

static __always_inline uintptr_t gen_or_mask(volatile void *p, size_t s)
{
	uintptr_t m = (((uintptr_t)1 << (msb(s) + 1)) -1) - s;

	return (uintptr_t)p & ~m;
}

static __always_inline uintptr_t gen_and_mask(size_t s)
{
	uintptr_t m = (((uintptr_t)1 << (msb(s) + 1)) - 1) -s;

	return (uintptr_t)m;
}



size_t bpf_ctx_size_map[] = {
	#define BPF_PROG_TYPE(_id, _name, prog_ctx_type, kern_ctx_type) \
		[_id] = sizeof(kern_ctx_type),
	#define BPF_MAP_TYPE(_id, _ops)
	#define BPF_LINK_TYPE(_id, _name)
	#include <linux/bpf_types.h>
	#undef BPF_PROG_TYPE
	#undef BPF_MAP_TYPE
	#undef BPF_LINK_TYPE
	0,
};
EXPORT_SYMBOL(bpf_ctx_size_map);
EXPORT_SYMBOL(sandboxes);
EXPORT_SYMBOL(sandbox_ctx);

static int __init bpf_sandbox_init(void)
{
	sandboxes = kmalloc(sizeof(union bpf_sandbox) * nr_cpu_ids, GFP_KERNEL);

	if (!sandboxes) {
		pr_err("Failed to allocate BPF sandboxes!\n");
		return -ENOMEM;
	}
	
	bpf_sandbox_and_mask = gen_and_mask(BPF_SANDBOX_SIZE);
	for (int i = 0; i < nr_cpu_ids; i++) {
		sandboxes[i].info.or_mask = gen_or_mask(sandboxes[i].mem.private, BPF_SANDBOX_SIZE);
	}

	pr_info("BPF Sandbox initialized successfully.\n");
	return 0;
}

core_initcall(bpf_sandbox_init);
