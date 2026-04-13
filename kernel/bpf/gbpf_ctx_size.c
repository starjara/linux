// kernel/bpf/gbpf_ctx_size.c
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/skbuff.h>
#include <net/xdp.h>

#include <linux/cpu.h>
//#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/skmsg.h>
#include <linux/perf_event.h>

#include <net/netfilter/nf_bpf_link.h>



size_t gbpf_ctx_size_map[] = {
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
EXPORT_SYMBOL(gbpf_ctx_size_map);

