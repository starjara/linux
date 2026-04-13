#include <linux/gbpf.h>
#include <linux/filter.h>
#include <linux/mm.h>
#include <linux/skbuff.h>
#include <net/xdp.h>
#include <linux/bpf.h>

// #define GBPF_DEBUG 1;

static void *gbpf_pkt_page_base(const void *ptr)
{
	return (void *)((unsigned long)ptr & PAGE_MASK);
}

static int gbpf_map_pkt_page(const struct bpf_prog *prog, const void *pkt_ptr)
{
	void *pkt_page;
	int err;

	pkt_page = gbpf_pkt_page_base(pkt_ptr);
	if (prog->aux->gaux->pkt_page == pkt_page)
		return 0;

	err = gbpf_call_map_ext(prog, pkt_page, PAGE_SIZE, PKT, 0, 0);
	if (err)
		return err;

	prog->aux->gaux->pkt_page = pkt_page;
	return 0;
}

static void *gbpf_copy_ctx_xdp(const struct xdp_buff *xdp,
			       const struct bpf_prog *prog)
{
	struct xdp_buff *shadow;
	void *shadow_ctx;
	void *pkt_page, *end;
	u32 data_off, end_off, meta_off;
	int err;

	pkt_page = gbpf_pkt_page_base(xdp->data);
	end = xdp->data_end;

	if (!pkt_page || !end)
		return NULL;

	/* 1-page packet buffer */
	if ((unsigned long)end < (unsigned long)xdp->data) {
	  pr_warn("[GBPF] Packet over the page boundary\n");
	  return NULL;
	}

	if ((unsigned long)end > (unsigned long)pkt_page + PAGE_SIZE) {
	  pr_warn("[GBPF] Packet over the page boundary\n");
	  return NULL;
	}	

	err = gbpf_map_pkt_page(prog, xdp->data);
	if (err) {
	  pr_warn("[GBPF] Mapping failed\n");
	  return NULL;
	}

	/* CTX Copy */
	shadow_ctx = page_to_virt(prog->aux->gaux->gbpf_page);
	shadow = shadow_ctx;

	data_off = (unsigned long)xdp->data - (unsigned long)pkt_page;
	end_off = (unsigned long)xdp->data_end - (unsigned long)pkt_page;

	shadow->data = (void *)(uintptr_t)(GBPF_PKT_BASE + data_off);
	shadow->data_end = (void *)(uintptr_t)(GBPF_PKT_BASE + end_off);

	if (xdp->data_meta) {
		if ((unsigned long)xdp->data_meta < (unsigned long)pkt_page ||
		    (unsigned long)xdp->data_meta >
			    (unsigned long)xdp->data_end) {
			return NULL;
		}
		meta_off = (unsigned long)xdp->data_meta - (unsigned long)pkt_page;
		shadow->data_meta = (void *)(uintptr_t)(GBPF_PKT_BASE + meta_off);
	} else {
		shadow->data_meta = NULL;
	}

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

	return (void *)prog->aux->gaux;
}

static void *gbpf_copy_ctx_skb(const struct sk_buff *skb,
			       const struct bpf_prog *prog)
{
	struct sk_buff *shadow;
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

	head_off = offset_in_page(skb->head);
	data_off = skb->data - skb->head;
	tail_off = skb_tail_pointer(skb) - skb->head;
	end_off = skb_end_offset(skb);

	if (head_off + end_off > PAGE_SIZE) {
		return NULL;
	}
	
	err = gbpf_map_pkt_page(prog, skb->head);
	if (err) {
	  pr_warn("[GBPF] Mapping failed\n");
	  return NULL;
	}

	/* CTX Copy */
	shadow_ctx = page_to_virt(prog->aux->gaux->gbpf_page);
	memcpy(shadow_ctx, skb, sizeof(*skb));
	shadow = shadow_ctx;

	shadow->head = (void *)(uintptr_t)(GBPF_PKT_BASE + head_off);
	shadow->data = (void *)(uintptr_t)(GBPF_PKT_BASE + head_off + data_off);
	shadow->tail = tail_off;
	shadow->end = end_off;

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
