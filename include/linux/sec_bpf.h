#ifndef __SEC_BPF_H__
#define __SEC_BPF_H__

#include <linux/filter.h>

int alloc_bpf_pgd(struct bpf_prog *prog);

#endif 
