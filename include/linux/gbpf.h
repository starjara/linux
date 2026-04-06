#ifndef _LINUX_GBPF_H
#define _LINUX_GBPF_H

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/netdevice.h>
#include <net/xdp.h>

#define GBPF_PAGE_SIZE 4096
#define GBPF_CONTEXT_SIZE 512
#define GBPF_STACK_SIZE (GBPF_PAGE_SIZE - GBPF_CONTEXT_SIZE)

#define GBPF_CTX_BASE 0x80000000ULL
#define GBPF_PKT_BASE 0x90000000ULL
#define GBPF_PKT_MAX_PAGES  64
#define GBPF_MAP_BASE 0xA0000000ULL

#define GBPF_MAP_WINDOW_SIZE 0x01000000UL   /* 16MB per map */
#define GBPF_CPU_WINDOW_SIZE 0x00010000UL   /* 64KB per cpu */

#define GBPF_STK_SAVE_S11       0
#define GBPF_STK_SAVE_S10       8
#define GBPF_STK_OLD_HGATP     16
#define GBPF_STK_CTX_BASE      24
#define GBPF_STK_PKT_BASE      32
#define GBPF_STK_MAP_BASE      40
#define GBPF_ORG_CTX           48
#define GBPF_STK_PROG_TYPE     56

#define GBPF_TR_FRAME_SIZE     64

struct page;


struct gbpf_map_desc {
	struct bpf_map *map;
	u32 map_slot;
	bool percpu;

	/* non-percpu base */
	u64 base;

	/* percpu base for each cpu */
	u64 percpu_base[NR_CPUS];
};

extern size_t gbpf_ctx_size_map[];

enum GBPF_MAP_TYPE {
  PKT,
  MAP,
  PERCPU_MAP,
};

struct gbpf_ops {
  int (*check_module)(void);
  int (*create_pgd)(struct bpf_prog *prog);
  int (*map)(struct bpf_prog *prog);
  int (*map_ext)(const struct bpf_prog *prog, const void *kaddr, size_t len, enum GBPF_MAP_TYPE type, int map_num, int cpu);
  void (*destroy_pgtable)(struct bpf_prog *prog);
  u32 (*get_vmid)(void);
  void (*inc_vmid)(void);
  void (*dec_vmid)(void);
};

// Module call related 
int gbpf_register_ops(const struct gbpf_ops *ops);
void gbpf_unregister_ops(const struct gbpf_ops *ops);

const struct gbpf_ops *pbpf_ops_get(void);

// Module functions
int gbpf_call_check_module(void);
int gbpf_call_create_pgd(struct bpf_prog *prog);
int gbpf_call_map(struct bpf_prog *prog);
int gbpf_call_map_ext(const struct bpf_prog *prog, const void *kaddr, size_t len, enum GBPF_MAP_TYPE type, int map_num, int cpu);
void gbpf_call_destroy_pgtable(struct bpf_prog *prog);
u32 gbpf_call_get_vmid(void);
void gbpf_call_inc_vmid(void);
void gbpf_call_dec_vmid(void);
static __always_inline void *gbpf_copy_ctx(const void *ctx, const struct bpf_prog *prog);

// Trampoline functions
u64 gbpf_helper_call_trampoline(u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5);

// Map functions
int gbpf_try_encode_kernel_map_ptr(u64 kptr, struct bpf_prog *prog, u64 *out);
int gbpf_init_prog_map_descs(struct bpf_prog *prog);


static inline unsigned long page_off(const void *p)
{
    return (unsigned long)p & (PAGE_SIZE - 1);
}

static inline u64 gbpf_encode_map_addr(u32 map_slot, u32 cpu_slot, u64 offset)
{
	return GBPF_MAP_BASE +
	       (u64)map_slot * GBPF_MAP_WINDOW_SIZE +
	       (u64)cpu_slot * GBPF_CPU_WINDOW_SIZE +
	       offset;
}

static inline int gbpf_decode_map_addr(u64 addr, u32 *map_slot,
				       u32 *cpu_slot, u32 *offset)
{
	u32 delta, rem;

	if (addr < GBPF_MAP_BASE)
		return -EINVAL;

	delta = addr - GBPF_MAP_BASE;
	*map_slot = delta / GBPF_MAP_WINDOW_SIZE;
	rem = delta % GBPF_MAP_WINDOW_SIZE;
	*cpu_slot = rem / GBPF_CPU_WINDOW_SIZE;
	*offset = rem % GBPF_CPU_WINDOW_SIZE;
	return 0;
}

/* 네 현재 어셈블리 기준. 커널 버전에 따라 반드시 확인 필요 */
#define GBPF_NETDEV_IFINDEX_OFF 224

struct gbpf_fake_netdev {
	u8 pad[GBPF_NETDEV_IFINDEX_OFF];
	int ifindex;
};

struct gbpf_xdp_shadow {
	struct xdp_buff ctx;
	struct xdp_rxq_info rxq;
	struct xdp_txq_info txq;
	struct gbpf_fake_netdev rx_dev;
	struct gbpf_fake_netdev tx_dev;
};

static void *gbpf_copy_xdp_with_nested_shadow(void *ctx, struct bpf_prog *prog)
{
	const struct xdp_buff *xdp = ctx;
	struct xdp_buff *shadow;
	struct gbpf_xdp_shadow *graph;
	struct page *shadow_page;
	void *shadow_pkt;
	void *shadow_ctx;
	void *base, *end;
	u32 base_off, data_off, end_off, meta_off;
	u32 copy_len;
	int err;

	if (!xdp || !prog || !prog->aux)
		return NULL;

	base = xdp->data_hard_start;
	end  = xdp->data_end;

	if (!base || !end)
		return NULL;

	if ((unsigned long)end < (unsigned long)base)
		return NULL;

	base_off = offset_in_page(base);
	copy_len = (unsigned long)end - (unsigned long)base;

	if (base_off + copy_len > PAGE_SIZE)
		return NULL;

	shadow_page = alloc_pages(GFP_KERNEL | __GFP_ZERO, 0);
	if (!shadow_page)
		return NULL;

	shadow_pkt = page_address(shadow_page);
	memcpy((char *)shadow_pkt + base_off, base, copy_len);

	err = gbpf_call_map_ext(prog,
				(void *)((unsigned long)shadow_pkt & PAGE_MASK),
				PAGE_SIZE,
				PKT, 0, 0);
	if (err) {
		__free_pages(shadow_page, 0);
		return NULL;
	}

	shadow_ctx = page_to_virt(prog->aux->gbpf_page);
	memset(shadow_ctx, 0, sizeof(struct gbpf_xdp_shadow));

	graph = shadow_ctx;
	shadow = &graph->ctx;

	/* 1. top-level xdp_buff copy */
	*shadow = *xdp;

	/* 2. packet pointer rewrite */
	data_off = (unsigned long)xdp->data - (unsigned long)base;
	end_off  = (unsigned long)xdp->data_end - (unsigned long)base;

	shadow->data =
		(void *)(uintptr_t)(GBPF_PKT_BASE + base_off + data_off);
	shadow->data_end =
		(void *)(uintptr_t)(GBPF_PKT_BASE + base_off + end_off);

	if (xdp->data_meta) {
		if ((unsigned long)xdp->data_meta < (unsigned long)base ||
		    (unsigned long)xdp->data_meta > (unsigned long)xdp->data_end) {
			__free_pages(shadow_page, 0);
			return NULL;
		}

		meta_off = (unsigned long)xdp->data_meta - (unsigned long)base;
		shadow->data_meta =
			(void *)(uintptr_t)(GBPF_PKT_BASE + base_off + meta_off);
	} else {
		shadow->data_meta = NULL;
	}

	shadow->data_hard_start =
		(void *)(uintptr_t)(GBPF_PKT_BASE + base_off);

	/* 3. rxq shadow */
	if (xdp->rxq) {
		graph->rxq = *xdp->rxq;
		shadow->rxq = &graph->rxq;

		/* 4. rxq->dev projection */
		memset(&graph->rx_dev, 0, sizeof(graph->rx_dev));
		if (xdp->rxq->dev)
			graph->rx_dev.ifindex = xdp->rxq->dev->ifindex;

		graph->rxq.dev = (struct net_device *)&graph->rx_dev;
	} else {
		shadow->rxq = NULL;
	}

	/* 5. txq shadow */
	/*
	if (xdp->txq) {
		graph->txq = *xdp->txq;
		shadow->txq = &graph->txq;

		// 6. txq->dev projection 
		memset(&graph->tx_dev, 0, sizeof(graph->tx_dev));
		if (xdp->txq->dev)
			graph->tx_dev.ifindex = xdp->txq->dev->ifindex;

		graph->txq.dev = (struct net_device *)&graph->tx_dev;
	} else {
		shadow->txq = NULL;
	}
	*/
	shadow->txq = NULL;

	pr_info("gbpf nested shadow ctx=%px rxq=%px rx_dev=%px ifindex=%d\n",
		shadow, shadow->rxq,
		shadow->rxq ? shadow->rxq->dev : NULL,
		xdp->rxq && xdp->rxq->dev ? xdp->rxq->dev->ifindex : -1);

	prog->aux->gbpf_shadow_pkt_page = shadow_page;
	return (void *)(uintptr_t)GBPF_CTX_BASE;
}

static __always_inline void *gbpf_copy_ctx(const void *ctx, const struct bpf_prog *prog)
{
  /*
  size_t ctx_size; 
  void *addr = NULL;
  void *ret = NULL;


  if(ctx) {
    prog->aux->orig_ctx = ctx;
    pr_info("orig_ctx : %px\tctx : %px\n", prog->aux->orig_ctx, ctx);
    ctx_size = gbpf_ctx_size_map[prog->type];

    if (ctx_size == 8)
      ctx_size = 64;

    
    if (prog->type == BPF_PROG_TYPE_XDP) {
      const struct xdp_buff *xdp = ctx;
      size_t len = (unsigned long)xdp->data_end - (unsigned long)xdp->data;
      struct xdp_buff *shadow;
      
      pr_info("pkt page addr : %px\n", xdp->data);
      
      gbpf_call_map_ext(prog, xdp->data, len, PKT);

      addr = page_to_virt(prog->aux->gbpf_page);
      memcpy(addr, xdp, sizeof(struct xdp_buff));   

      shadow = addr;

      shadow->data = (void *)(uintptr_t)(GBPF_PKT_BASE + page_off(xdp->data));

      if (virt_to_page((void *)((unsigned long)xdp->data_end & PAGE_MASK)) == prog->aux->gbpf_pkt_page)
	shadow->data_end = (void *)(uintptr_t)(GBPF_PKT_BASE + page_off(xdp->data_end));

      if (xdp->data_meta &&
	  virt_to_page((void *)((unsigned long)xdp->data_meta & PAGE_MASK)) == prog->aux->gbpf_pkt_page)
	shadow->data_meta = (void *)(uintptr_t)(GBPF_PKT_BASE + page_off(xdp->data_meta));

      //return (void *)(uintptr_t)GBPF_CTX_BASE; 
      return prog->aux->orig_ctx;
    }
    else if (prog->type == BPF_PROG_TYPE_SOCKET_FILTER) {
      const struct sk_buff *skb = ctx;
      unsigned char *head = skb->head;
      size_t len = skb_end_offset(skb);
      struct sk_buff *shadow;

      pr_info("Socket filter type\n");
      pr_info("pkt page addr : %px\n", skb->head);
      
      gbpf_call_map_ext(prog, head, len, PKT);
      
      addr = page_to_virt(prog->aux->gbpf_page);
      memcpy(addr, skb, sizeof(struct sk_buff));   
      
      shadow = addr;
      shadow->head = (void *)(uintptr_t)(GBPF_PKT_BASE + page_off(skb->head));
      
      if (virt_to_page((void *)((unsigned long)skb->data & PAGE_MASK)) == prog->aux->gbpf_pkt_page)
	shadow->data = (void *)(uintptr_t)(GBPF_PKT_BASE + page_off(skb->data));
      
      //return (void *)(uintptr_t)GBPF_CTX_BASE; 
      return prog->aux->orig_ctx;

    }

    addr = page_to_virt(prog->aux->gbpf_page);
    memcpy(addr, ctx, ctx_size);
    // ret = addr;
    ret = (void *)(uintptr_t)GBPF_CTX_BASE;

    pr_info("CTX ADDR = %px\n", addr);
    pr_info("CTX SIZE = %lu\n", ctx_size);

  }

  //return ret;
  return prog->aux->orig_ctx;
*/
  size_t ctx_size;
  void *addr;
  
  if (!ctx)
    return NULL;
  
  prog->aux->orig_ctx = ctx;
  ctx_size = gbpf_ctx_size_map[prog->type];
  if (ctx_size == 8)
    ctx_size = 64;
  
  /*
  if (prog->type == BPF_PROG_TYPE_XDP) {
    const struct xdp_buff *xdp = ctx;
    size_t len = (unsigned long)xdp->data_end - (unsigned long)xdp->data;
    struct xdp_buff *shadow;
    shadow_page = alloc_pages(GFP_KERNEL | __GFP_ZERO, 0);
    if (!shadow_page)
        return NULL;

    shadow_pkt = page_address(shadow_page);


    
    gbpf_call_map_ext(prog, xdp->data, len, PKT);
    addr = page_to_virt(prog->aux->gbpf_page);
    memcpy(addr, xdp, sizeof(*xdp));
    shadow	 = addr;
    shadow->data = (void *)(uintptr_t)(GBPF_PKT_BASE + page_off(xdp->data));
    
    if (virt_to_page((void *)((unsigned long)xdp->data_end & PAGE_MASK)) == prog->aux->gbpf_pkt_page)
      shadow->data_end = (void *)(uintptr_t)(GBPF_PKT_BASE + page_off(xdp->data_end));
    if (xdp->data_meta	&&
	virt_to_page((void *)((unsigned long)xdp->data_meta & PAGE_MASK)) == prog->aux->gbpf_pkt_page)
      shadow->data_meta = (void *)(uintptr_t)(GBPF_PKT_BASE + page_off(xdp->data_meta));

    return (void *)(uintptr_t)GBPF_CTX_BASE;
  }
  */
  if (prog->type == BPF_PROG_TYPE_XDP) {

    /*
    void *ret = gbpf_copy_xdp_with_nested_shadow(ctx, prog);
    return ret;
    */
    
    const struct xdp_buff *xdp = ctx;
    struct xdp_buff *shadow;
    struct page *shadow_page;
    void *shadow_pkt;
    void *shadow_ctx;
    void *base, *end;
    u32 base_off, data_off, end_off, meta_off;
    u32 copy_len;
    int err;

    /*
     * 일단 1-page packet buffer만 지원
     * data_hard_start ~ data_end 전체가 한 페이지 안에 있어야 함
     */
    base = xdp->data_hard_start;
    end  = xdp->data_end;

    if ((unsigned long)end < (unsigned long)base)
      return NULL;

    base_off = offset_in_page(base);
    copy_len = (unsigned long)end - (unsigned long)base;

    if (base_off + copy_len > PAGE_SIZE)
      return NULL;

    shadow_page = alloc_pages(GFP_KERNEL | __GFP_ZERO, 0);
    if (!shadow_page)
      return NULL;

    shadow_pkt = page_address(shadow_page);

    memcpy((char *)shadow_pkt + base_off, base, copy_len);

    err = gbpf_call_map_ext(prog,
                            (void *)((unsigned long)shadow_pkt & PAGE_MASK),
                            PAGE_SIZE,
                            PKT, 0, 0);
    if (err) {
      __free_pages(shadow_page, 0);
      return NULL;
    }

    shadow_ctx = page_to_virt(prog->aux->gbpf_page);
    memcpy(shadow_ctx, xdp, sizeof(*xdp));
    shadow = shadow_ctx;

    data_off = (unsigned long)xdp->data - (unsigned long)base;
    end_off  = (unsigned long)xdp->data_end - (unsigned long)base;

    shadow->data = (void *)(uintptr_t)(GBPF_PKT_BASE + base_off + data_off);
    shadow->data_end = (void *)(uintptr_t)(GBPF_PKT_BASE + base_off + end_off);

    if (xdp->data_meta) {
      if ((unsigned long)xdp->data_meta < (unsigned long)base ||
          (unsigned long)xdp->data_meta > (unsigned long)xdp->data_end) {
        __free_pages(shadow_page, 0);
        return NULL;
      }

      meta_off = (unsigned long)xdp->data_meta - (unsigned long)base;
      shadow->data_meta =
        (void *)(uintptr_t)(GBPF_PKT_BASE + base_off + meta_off);
    }

    shadow->data_hard_start =
      (void *)(uintptr_t)(GBPF_PKT_BASE + base_off);
    pr_info("shadow_data : %px\n", shadow->data);
    pr_info("shadow_data_hard_start : %px\n", shadow->data_hard_start);

    /*
    shadow->rxq = GBPF_CTX_BASE + sizeof(struct xdp_buff);
    pr_info("shadow_rxq: %px\n", shadow->rxq);
    shadow->rxq->dev = (void *)(shadow->rxq + sizeof(struct xdp_rxq_info));
    pr_info("shadow_rxq_dev: %px\n", shadow->rxq->dev);
    shadow->rxq->dev->ifindex = xdp->rxq->dev->ifindex;
    pr_info("shadow_rxq_dev_ifindex: %px\n", shadow->rxq->dev->ifindex);
    */

    struct xdp_rxq_info *shadow_rxq_host;
    struct gbpf_fake_netdev *shadow_dev_host;
    unsigned long rxq_guest, dev_guest;

    rxq_guest = GBPF_CTX_BASE + sizeof(struct xdp_buff);
    dev_guest = rxq_guest + sizeof(struct xdp_rxq_info);

    shadow_rxq_host = (struct xdp_rxq_info *)((char *)shadow_ctx +
					    sizeof(struct xdp_buff));
    shadow_dev_host = (struct gbpf_fake_netdev *)((char *)shadow_ctx +
						sizeof(struct xdp_buff) +
						sizeof(struct xdp_rxq_info));

    shadow->rxq = (struct xdp_rxq_info *)rxq_guest;
    pr_info("shadow_rxq guest: %px\n", shadow->rxq);

    *shadow_rxq_host = *xdp->rxq;
    shadow_rxq_host->dev = (struct net_device *)dev_guest;
    pr_info("shadow_rxq_dev guest: %px\n", shadow_rxq_host->dev);

    memset(shadow_dev_host, 0, sizeof(*shadow_dev_host));
    shadow_dev_host->ifindex = xdp->rxq->dev->ifindex;
    pr_info("shadow_rxq_dev_ifindex host: %d\n", shadow_dev_host->ifindex);
    
    /* cleanup path에서 free 필요 */
    prog->aux->gbpf_shadow_pkt_page = shadow_page;

    return (void *)(uintptr_t)GBPF_CTX_BASE;
  }
  
  if (prog->type == BPF_PROG_TYPE_SOCKET_FILTER) {
    const struct sk_buff *skb = ctx;
    struct sk_buff *shadow;
    struct page *shadow_page;
    void *shadow_pkt;
    void *shadow_ctx;
    u32 head_off, data_off, tail_off, end_off;
    int err;

    /* 일단 1-page linear skb만 지원 */
    if (skb_headlen(skb) > PAGE_SIZE)
        return NULL;
    if (skb_is_nonlinear(skb))
        return NULL;

    shadow_page = alloc_pages(GFP_KERNEL | __GFP_ZERO, 0);
    if (!shadow_page)
        return NULL;

    shadow_pkt = page_address(shadow_page);

    head_off = offset_in_page(skb->head);
    data_off = skb->data - skb->head;
    tail_off = skb_tail_pointer(skb) - skb->head;
    end_off  = skb_end_offset(skb);

    if (head_off + end_off > PAGE_SIZE) {
        __free_pages(shadow_page, 0);
        return NULL;
    }

    memcpy((char *)shadow_pkt + head_off, skb->head, end_off);

    err = gbpf_call_map_ext(prog,
                            (void *)((unsigned long)shadow_pkt & PAGE_MASK),
                            PAGE_SIZE,
                            PKT, 0, 0);
    if (err) {
        __free_pages(shadow_page, 0);
        return NULL;
    }

    shadow_ctx = page_to_virt(prog->aux->gbpf_page);
    memcpy(shadow_ctx, skb, sizeof(*skb));
    shadow = shadow_ctx;

    shadow->head = (void *)(uintptr_t)(GBPF_PKT_BASE + head_off);
    shadow->data = (void *)(uintptr_t)(GBPF_PKT_BASE + head_off + data_off);
    shadow->tail = tail_off;
    shadow->end  = end_off;

    /* 나중에 cleanup path에서 shadow_page free 필요 */
    prog->aux->gbpf_shadow_pkt_page = shadow_page;

    return (void *)(uintptr_t)GBPF_CTX_BASE;
  }

  /*
  if (prog->type == BPF_PROG_TYPE_SOCKET_FILTER) {
    const struct sk_buff	*skb  = ctx;
    unsigned char		*head = skb->head;
    struct sk_buff		*shadow;

    gbpf_call_map_ext(prog, head, skb_end_offset(skb), PKT);

    addr = page_to_virt(prog->aux->gbpf_page);
    memcpy(addr, skb, sizeof(*skb));
    shadow = addr;
    shadow->head = (void *)(uintptr_t)(GBPF_PKT_BASE + page_off(skb->head));
    if (virt_to_page((void *)((unsigned long)skb->data & PAGE_MASK)) == prog->aux->gbpf_pkt_page)
      shadow->data = (void *)(uintptr_t)(GBPF_PKT_BASE + page_off(skb->data));
    
    return (void *)(uintptr_t)GBPF_CTX_BASE;
  }
  */
  
  addr = page_to_virt(prog->aux->gbpf_page);
  memcpy(addr, ctx, ctx_size);
  return (void *)(uintptr_t)GBPF_CTX_BASE;
}

#endif /* _LINUX_GBPF_H  */
