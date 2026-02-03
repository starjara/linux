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
	sandboxes = kzalloc(sizeof(union bpf_sandbox) * nr_cpu_ids, GFP_KERNEL);

	if (!sandboxes) {
		pr_err("Failed to allocate BPF sandboxes!\n");
		return -ENOMEM;
	}
	
	for (int i = 0; i < nr_cpu_ids; i++) {
		struct bpf_sandbox_info *info = &sandboxes[i].info;
		void *mem = &sandboxes[i].mem.data[0];

		info->or_mask = (u64)mem;
		info->and_mask = (u64)(BPF_SANDBOX_SIZE - 1);
	}

	pr_info("BPF Sandbox initialized successfully.\n");
	return 0;
}

core_initcall(bpf_sandbox_init);
