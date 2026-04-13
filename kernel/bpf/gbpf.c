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
  void *pkt_page, *end;
  u32 data_off, end_off, meta_off;
  int err;
  
  pkt_page = xdp->data_hard_start;
  end = xdp->data_end;
  
#ifdef GBPF_DEBUG
  pr_info("XDP Packet_hard addr : %px\n", xdp->data_hard_start);
  pr_info("XDP Packet addr : %px\n", xdp->data);
  pr_info("XDP Packet end  : %px\n", xdp->data_end);
  pr_info("XDP Packet len  : %px\n", end - xdp->data);
#endif

  /* 1-page packet buffer */
  if ((unsigned long)end < (unsigned long)xdp->data) {
    pr_warn("[GBPF] Packet over the page boundary\n");
    return NULL;
  }

  if ((unsigned long)end > (unsigned long)pkt_page + PAGE_SIZE) {
    pr_warn("[GBPF] Packet over the page boundary\n");
    return NULL;
  }	

  data_off = (unsigned long)xdp->data - (unsigned long)pkt_page;
  end_off = (unsigned long)xdp->data_end - (unsigned long)pkt_page;
 
  err = gbpf_map_pkt_page(prog, xdp->data);
  
  if (err) {
    pr_warn("[GBPF] Mapping failed\n");
    return NULL;
  }

  /* CTX Copy */
  shadow = page_to_virt(prog->aux->gaux->gbpf_page);
  
  shadow->data = (void *)(uintptr_t)(GBPF_PKT_BASE + data_off);
  shadow->data_end = (void *)(uintptr_t)(GBPF_PKT_BASE + end_off);

  shadow->data_hard_start = (void *)(uintptr_t)GBPF_PKT_BASE;
  shadow->frame_sz = xdp->frame_sz;
 
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

#ifdef GBPF_DEBUG
  pr_info("CTX Packet addr : %px\n", shadow->data);
  pr_info("CTX Packet end  : %px\n", shadow->data_end);
  pr_info("CTX Packet len  : %px\n", shadow->data_end - shadow->data);
#endif
  
  /*
   * xdp->rxq는 helper가 ifindex 등을 보게 될 수 있으므로
   * guest ctx page 안에 shadow를 구성한다.
   */
  if (xdp->rxq) {
    struct xdp_rxq_info *shadow_rxq_host;
    //struct net_device *shadow_dev_host;
    char *shadow_dev_host;
    unsigned long rxq_guest, dev_guest;
    size_t dev_size = offsetof(struct net_device, ifindex) + sizeof(int);
    int ifindex = xdp->rxq->dev ? xdp->rxq->dev->ifindex : 0;
    
    rxq_guest = GBPF_CTX_BASE + sizeof(struct xdp_buff);
    dev_guest = rxq_guest + sizeof(struct xdp_rxq_info);
    
    shadow_rxq_host =
      (struct xdp_rxq_info *)((char *)shadow +
			      sizeof(struct xdp_buff));
    shadow_dev_host =
      (char *)shadow +
      sizeof(struct xdp_buff) +
      sizeof(struct xdp_rxq_info);
  
    if (prog->aux->gaux->cached_xdp_rxq != xdp->rxq ||
	prog->aux->gaux->cached_xdp_ifindex != ifindex) {
      *shadow_rxq_host = *xdp->rxq;
      shadow_rxq_host->dev = (struct net_device *)dev_guest;
      
      memset(shadow_dev_host, 0, dev_size);
      
      *(int *)(shadow_dev_host + offsetof(struct net_device, ifindex)) =
	ifindex;
      
      prog->aux->gaux->cached_xdp_rxq = xdp->rxq;
      prog->aux->gaux->cached_xdp_ifindex = ifindex;
    }
    shadow->rxq = (struct xdp_rxq_info *)rxq_guest;
  } else {
    prog->aux->gaux->cached_xdp_rxq = NULL;
    prog->aux->gaux->cached_xdp_ifindex = 0;
    shadow->rxq = NULL;
  }

  /*
   * 현재 구현에서는 txq shadow는 사용하지 않는다.
   */
  shadow->txq = NULL;
  
  return (void *)prog->aux->gaux;
}

/*
static void gbpf_copy_skb_ctx(struct sk_buff *dst, const struct sk_buff *src)
{
  dst->len = src->len;
  dst->pkt_type = src->pkt_type;
  dst->mark = src->mark;
  dst->queue_mapping = src->queue_mapping;
  dst->protocol = src->protocol;
  dst->vlan_present = src->vlan_present;
  dst->vlan_tci = src->vlan_tci;
  dst->vlan_proto = src->vlan_proto;
  dst->priority = src->priority;
  dst->ingress_ifindex = src->ingress_ifindex;
  dst->ifindex = src->ifindex;
  dst->tc_index = src->tc_index;
  dst->data = src->data;
  dst->data_end = src->data_end;
  dst->napi_id = src->napi_id;
  dst->famil = src->family;
  dst->remote_ip4 = src->remote_ip4;
  dst->local_ip4 = src->remote_ip4;
  dst->remote_ip6 = src->remote_ip6;
  dst->local_ip6 = src->remote_ip6;
  dst->remote_port = src->remote_port;
  dst->local_port = src->local_port;
  dst->data_meta = src->data_meta;
  dst->flow_keys = src->flow_keys;
  dst->tstamp = src->tstmap;
  dst->wire_len = src->wire_len;
  dst->sk = src->sk;
  dst->gso_segs = src->gso_segs;
  dst->tstamp_type = src->tstamp_type;
  dst->hwtstamp = src->hwtstamp;
}
*/

static void gbpf_copy_skb_hard(struct sk_buff *dst, const struct sk_buff *src)
{
	memset(dst, 0, sizeof(*dst));

	/* __sk_buff-visible scalar-ish fields */
	dst->len            = src->len;
	dst->pkt_type       = src->pkt_type;
	dst->mark           = src->mark;
	dst->queue_mapping  = src->queue_mapping;
	dst->protocol       = src->protocol;
	dst->priority       = src->priority;
	dst->skb_iif        = src->skb_iif;
	dst->tc_index       = src->tc_index;
	dst->hash           = src->hash;
	dst->priority       = src->priority;
	dst->tstamp         = src->tstamp;
	memcpy(dst->cb, src->cb, sizeof(dst->cb));

	/* vlan */
	dst->vlan_all       = src->vlan_all;
	dst->vlan_tci       = src->vlan_tci;
	dst->vlan_proto     = src->vlan_proto;

	/* ifindex path */
	dst->dev            = src->dev;

	/* data / data_end path */
	//dst->head           = src->head;
	//dst->data           = src->data;
	//dst->tail           = src->tail;
	//dst->end            = src->end;
	//dst->mac_header     = src->mac_header;
	dst->network_header = src->network_header;
	dst->transport_header = src->transport_header;

#ifdef CONFIG_NET_RX_BUSY_POLL
	dst->napi_id        = src->napi_id;
#endif

#ifdef CONFIG_SKB_EXTENSIONS
	dst->active_extensions = src->active_extensions;
#endif
}

static void *gbpf_copy_ctx_skb(const struct sk_buff *skb,
			       const struct bpf_prog *prog)
{
	struct sk_buff *shadow;
	void *shadow_ctx;
	u32 head_off, data_off, tail_off, end_off;
	int err;

#ifdef GBPF_DEBUG
	pr_info("SKB Packet addr : %px\n", skb->data);
#endif
	
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
	//memcpy(shadow_ctx, skb, sizeof(*skb));
	gbpf_copy_skb_hard(shadow_ctx, skb);

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
