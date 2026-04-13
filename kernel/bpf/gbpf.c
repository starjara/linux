#include <linux/gbpf.h>
#include <linux/filter.h>
#include <linux/mm.h>
#include <linux/skbuff.h>
#include <net/xdp.h>
#include <linux/bpf.h>

#define GBPF_DEBUG 1;

static void *gbpf_copy_ctx_xdp(const struct xdp_buff *xdp,
			       const struct bpf_prog *prog)
{
	struct xdp_buff *shadow;
	void *shadow_pkt;
	void *shadow_ctx;
	void *base, *end;
	u32 base_off, data_off, end_off, meta_off;
	u32 copy_len;
	int err;

	if (!xdp || !prog || !prog->aux)
		return NULL;

	//base = xdp->data_hard_start;
	base = xdp->data;
	end = xdp->data_end;

	if (!base || !end)
		return NULL;


	/* 1-page packet buffer만 지원 */
	if ((unsigned long)end < (unsigned long)base)
		return NULL;

	base_off = offset_in_page(base);
	copy_len = (unsigned long)end - (unsigned long)base;

	if (base_off + copy_len > PAGE_SIZE)
		return NULL;

	shadow_pkt = page_to_virt(prog->aux->gbpf_shadow_pkt_page);
	memcpy((char *)shadow_pkt + base_off, base, copy_len);

	// Bug??
	//pr_info("len : %lu\n", copy_len);

	/* CTX Copy */
	shadow_ctx = page_to_virt(prog->aux->gaux->gbpf_page);
	shadow = shadow_ctx;

	data_off = (unsigned long)xdp->data - (unsigned long)base;
	end_off = (unsigned long)xdp->data_end - (unsigned long)base;

	shadow->data = (void *)(uintptr_t)(GBPF_PKT_BASE + base_off + data_off);
	shadow->data_end =
		(void *)(uintptr_t)(GBPF_PKT_BASE + base_off + end_off);

	if (xdp->data_meta) {
		if ((unsigned long)xdp->data_meta < (unsigned long)base ||
		    (unsigned long)xdp->data_meta >
			    (unsigned long)xdp->data_end) {
			return NULL;
		}

		meta_off = (unsigned long)xdp->data_meta - (unsigned long)base;
		shadow->data_meta =
			(void *)(uintptr_t)(GBPF_PKT_BASE + base_off + meta_off);
	} else {
		shadow->data_meta = NULL;
	}

	/*
	shadow->data_hard_start =
		(void *)(uintptr_t)(GBPF_PKT_BASE + base_off);
	*/

	/*
	 * xdp->rxq는 helper가 ifindex 등을 보게 될 수 있으므로
	 * guest ctx page 안에 shadow를 구성한다.
	 */
	if (xdp->rxq) {
		struct xdp_rxq_info *shadow_rxq_host;
		struct net_device *shadow_dev_host;
		unsigned long rxq_guest, dev_guest;

		rxq_guest = GBPF_CTX_BASE + sizeof(struct xdp_buff);
		dev_guest = rxq_guest + sizeof(struct xdp_rxq_info);

		shadow_rxq_host =
			(struct xdp_rxq_info *)((char *)shadow_ctx +
						sizeof(struct xdp_buff));
		shadow_dev_host =
			(struct net_device *)((char *)shadow_ctx +
						    sizeof(struct xdp_buff) +
						    sizeof(struct xdp_rxq_info));

		*shadow_rxq_host = *xdp->rxq;
		shadow_rxq_host->dev = (struct net_device *)dev_guest;

		memset(shadow_dev_host, 0, sizeof(*shadow_dev_host));
		if (xdp->rxq->dev)
			shadow_dev_host->ifindex = xdp->rxq->dev->ifindex;

		shadow->rxq = (struct xdp_rxq_info *)rxq_guest;
	} else {
		shadow->rxq = NULL;
	}

	/*
	 * 현재 구현에서는 txq shadow는 사용하지 않는다.
	 */
	shadow->txq = NULL;

	//return (void *)(uintptr_t)GBPF_CTX_BASE;
	return (void *)prog->aux->gaux;
}

static void *gbpf_copy_ctx_skb(const struct sk_buff *skb,
			       const struct bpf_prog *prog)
{
	struct sk_buff *shadow;
	void *shadow_pkt;
	void *shadow_ctx;
	u32 head_off, data_off, tail_off, end_off;
	int err;

	if (!skb || !prog || !prog->aux)
		return NULL;

	/* 1-page linear skb만 지원 */
	if (skb_headlen(skb) > PAGE_SIZE)
		return NULL;
	if (skb_is_nonlinear(skb))
		return NULL;

	shadow_pkt = page_address(prog->aux->gbpf_shadow_pkt_page);

	head_off = offset_in_page(skb->head);
	data_off = skb->data - skb->head;
	tail_off = skb_tail_pointer(skb) - skb->head;
	end_off = skb_end_offset(skb);

	if (head_off + end_off > PAGE_SIZE) {
		return NULL;
	}
	

	memcpy((char *)shadow_pkt + head_off, skb->head, end_off);

	/* CTX Copy */
	shadow_ctx = page_to_virt(prog->aux->gaux->gbpf_page);
	memcpy(shadow_ctx, skb, sizeof(*skb));
	shadow = shadow_ctx;

	shadow->head = (void *)(uintptr_t)(GBPF_PKT_BASE + head_off);
	shadow->data = (void *)(uintptr_t)(GBPF_PKT_BASE + head_off + data_off);
	shadow->tail = tail_off;
	shadow->end = end_off;

	//return (void *)(uintptr_t)GBPF_CTX_BASE;
	return (void *)prog->aux->gaux;
}

static void *gbpf_copy_ctx_generic(const void *ctx,
				   const struct bpf_prog *prog,
				   size_t ctx_size)
{
	void *addr;

	if (!ctx || !prog || !prog->aux)
		return NULL;

	addr = page_to_virt(prog->aux->gaux->gbpf_page);
	memcpy(addr, ctx, ctx_size);

	//return (void *)(uintptr_t)GBPF_CTX_BASE;
	return (void *)prog->aux->gaux;
}

void *gbpf_copy_ctx(const void *ctx, const struct bpf_prog *prog)
{
	size_t ctx_size;

	if (!ctx)
		return NULL;

	prog->aux->gaux->orig_ctx = ctx;

#ifdef GBPF_DEBUG
	pr_info("prog->aux->gaux: %px\n", prog->aux->gaux);
#endif

	ctx_size = gbpf_ctx_size_map[prog->type];
	if (ctx_size == 8)
		ctx_size = 64;

	switch (prog->type) {
	case BPF_PROG_TYPE_XDP:
		return gbpf_copy_ctx_xdp(ctx, prog);
	case BPF_PROG_TYPE_SOCKET_FILTER:
		return gbpf_copy_ctx_skb(ctx, prog);
	default:
		return gbpf_copy_ctx_generic(ctx, prog, ctx_size);
	}
}
EXPORT_SYMBOL_GPL(gbpf_copy_ctx);
