/* Garden : Append Macro and Definition to Sandbox something */

#ifndef _BPF_SANDBOX_H
#define _BPF_SANDBOX_H

#include <linux/types.h>

#define BPF_SANDBOX_SIZE 2048

#define BPF_SANDBOX_OR_MASK_OFFSET -8
#define BPF_SANDBOX_AND_MASK_OFFSET -16
#define BPF_SANDBOX_ORIG_SP_OFFSET -24

#define IS_SANDBOX_ENABLED(type) ( \
		(type) == BPF_PROG_TYPE_XDP \
)



struct bpf_sandbox_info {
	u64	prog_brk;
	u64	stack_end;
	u64	free_size;
	u64	and_mask;
	u64	or_mask;
	u64	kern_ctx;
};

struct bpf_sandbox_mem{
	u8 raw_info[2048];
	u8 private[2048];
};

union bpf_sandbox {
	struct bpf_sandbox_info info;
	struct bpf_sandbox_mem mem;
};

extern union bpf_sandbox *sandboxes;



#endif
