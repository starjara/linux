#ifndef _LINUX_BPF_CTX_H_SAFE
#define _LINUX_BPF_CTX_H_SAFE


#include <linux/bpf.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/perf_event.h>

#include <net/xdp.h>
#include <net/sock.h>
#include <net/busy_poll.h>
#include <net/sch_generic.h>

#define BITMAP_COMPRESSION 4
#define XDP_BITMAP_SIZE 6
#define PERF_EVENT_BITMAP_SIZE 32
#define SOCKET_FILTER_BITMAP_SIZE 64

#define IS_SANDBOX_CTX_SUPPORTED(type) ( \
		type == BPF_PROG_TYPE_SOCKET_FILTER \
		|| type == BPF_PROG_TYPE_PERF_EVENT \
		|| type == BPF_PROG_TYPE_XDP \
		|| type == BPF_PROG_TYPE_KPROBE \
		)

struct bpf_skb_data_end_mirror {
	struct qdisc_skb_cb qdisc_cb;
	void *data_meta;
	void *data_end;
};

void bpf_sync_kernel_ctx(const struct bpf_prog *prog, const void *kernel_ctx, void *bpf_ctx);
void record_ctx_accesses(void *verifier_env);

void bpf_sync_sk_filter_ctx(const struct bpf_prog *prog, const struct sk_buff *kernel_ctx, struct __sk_buff *bpf_ctx);

void bpf_sync_xdp_ctx(const struct bpf_prog *prog, const struct xdp_buff *kernel_ctx, struct xdp_md *bpf_ctx);



#endif
