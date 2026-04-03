#ifndef _LINUX_GBPF_H
#define _LINUX_GBPF_H

#include <linux/types.h>
#include <linux/bpf.h>
#include <net/xdp.h>

#define GBPF_PAGE_SIZE 4096
#define GBPF_CONTEXT_SIZE 512
#define GBPF_STACK_SIZE (GBPF_PAGE_SIZE - GBPF_CONTEXT_SIZE)

#define GBPF_CTX_BASE 0x80000000ULL
#define GBPF_PKT_BASE 0x90000000ULL
#define GBPF_PKT_MAX_PAGES  64
#define GBPF_MAP_BASE 0xA0000000ULL

#define GBPF_STK_SAVE_S11       0
#define GBPF_STK_SAVE_S10       8
#define GBPF_STK_OLD_HGATP     16
#define GBPF_STK_CTX_BASE      24
#define GBPF_STK_PKT_BASE      32
#define GBPF_STK_MAP_BASE      40
#define GBPF_ORG_CTX           48
#define GBPF_STK_HELPER_ID     56

#define GBPF_TR_FRAME_SIZE     64

struct page;


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
  int (*map_ext)(const struct bpf_prog *prog, const void *kaddr, size_t len, enum GBPF_MAP_TYPE type);
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
int gbpf_call_map_ext(const struct bpf_prog *prog, const void *kaddr, size_t len, enum GBPF_MAP_TYPE type);
void gbpf_call_destroy_pgtable(struct bpf_prog *prog);
u32 gbpf_call_get_vmid(void);
void gbpf_call_inc_vmid(void);
void gbpf_call_dec_vmid(void);
static __always_inline void *gbpf_copy_ctx(const void *ctx, const struct bpf_prog *prog);

// Trampoline functions
u64 gbpf_helper_call_trampoline(u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5);


static inline unsigned long page_off(const void *p)
{
    return (unsigned long)p & (PAGE_SIZE - 1);
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
                            PKT);
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
    pr_info("shadow_data : %px\n", shadow->data);
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
                            PKT);
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
