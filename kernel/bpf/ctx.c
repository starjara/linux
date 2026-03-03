#include <linux/bpf_ctx.h>



/*
void bpf_sync_sk_filter_ctx(const struct bpf_prog *prog, const struct sk_buff *kernel_ctx, struct __sk_buff *bpf_ctx)
{
	struct qdisc_skb_cb *qdisc_cb = qdisc_skb_cb(kernel_ctx);
	if (qdisc_cb && virt_addr_valid(qdisc_cb)){
		memcpy(qdisc_cb->data, bpf_ctx->cb, sizeof(bpf_ctx->cb));
			
	}

}

void bpf_sync_xdp_ctx(const struct bpf_prog *prog, const struct xdp_buff *kernel_ctx, struct xdp_md *bpf_ctx)
{
	struct xdp_rxq_info *rxq = kernel_ctx->rxq;
	if (bpf_prog_is_offloaded(prog->aux) && rxq && virt_addr_valid(rxq))
		rxq->queue_index = bpf_ctx->rx_queue_index;
}
*/


void bpf_sync_kernel_ctx(const struct bpf_prog *prog, const void *kernel_ctx, void *bpf_ctx)
{
	switch (prog->type)
	{
		case BPF_PROG_TYPE_SOCKET_FILTER:
			bpf_sync_sk_filter_ctx(prog, kernel_ctx, bpf_ctx);
			break;
		case BPF_PROG_TYPE_XDP:
			bpf_sync_xdp_ctx(prog, kernel_ctx, bpf_ctx);
			break;
		case BPF_PROG_TYPE_PERF_EVENT:
			break;
		case BPF_PROG_TYPE_KPROBE:
			break;
		default:
			break;
	}
}





static inline void __bpf_ctx_bitmap_alloc(struct bpf_prog *prog, int nbits)
{
	prog->ctx_read_write_bitmap = bitmap_zalloc(nbits, GFP_KERNEL);
	prog->ctx_write_bitmap = bitmap_zalloc(nbits, GFP_KERNEL);
}



void bpf_ctx_bitmap_alloc(struct bpf_prog *prog, int type)
{
	switch (type) {
		case BPF_PROG_TYPE_XDP:
			__bpf_ctx_bitmap_alloc(prog, XDP_BITMAP_SIZE);
			break;
		case BPF_PROG_TYPE_SOCKET_FILTER:
			__bpf_ctx_bitmap_alloc(prog, SOCKET_FILTER_BITMAP_SIZE);
			break;
		case BPF_PROG_TYPE_PERF_EVENT:
			__bpf_ctx_bitmap_alloc(prog, PERF_EVENT_BITMAP_SIZE);
			break;
		default:
			break;
	}
}
EXPORT_SYMBOL(bpf_ctx_bitmap_alloc);
EXPORT_SYMBOL(bpf_sync_kernel_ctx);
