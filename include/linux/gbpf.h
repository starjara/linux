#ifndef _LINUX_GBPF_H
#define _LINUX_GBPF_H

#include <linux/types.h>
#include <linux/bpf.h>
#include <net/xdp.h>
#include <linux/types.h>

#define GBPF_PAGE_SIZE 4096
#define GBPF_CONTEXT_SIZE 512
#define GBPF_STACK_SIZE (GBPF_PAGE_SIZE - GBPF_CONTEXT_SIZE)

#define GBPF_CTX_BASE 0x80000000ULL
#define GBPF_PKT_BASE 0x90000000ULL
#define GBPF_PKT_MAX_PAGES  64
#define GBPF_MAP_BASE 0xA0000000ULL

struct page;
/*
struct sk_buff;
struct sock;
struct seccomp_data;
struct bpf_prog_aux;
struct xdp_rxq_info;
struct xdp_buff;
struct sock_reuseport;
struct ctl_table;
struct ctl_table_header;
*/

extern size_t gbpf_ctx_size_map[];

enum GBPF_MAP_TYPE {
  PKT,
  MAP,
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
  size_t ctx_size; 
  void *addr = NULL;
  void *ret = NULL;


  if(ctx) {
    ctx_size = gbpf_ctx_size_map[prog->type];

    if (ctx_size == 8)
      ctx_size = 64;

    if (prog->type == BPF_PROG_TYPE_XDP) {
      const struct xdp_buff *xdp = ctx;
      size_t len = (unsigned long)xdp->data_end - (unsigned long)xdp->data;
      struct xdp_buff *shadow;
      
      gbpf_call_map_ext(prog, xdp->data, len, PKT);

      addr = page_to_virt(prog->aux->gbpf_page);
      memcpy(addr, xdp, sizeof(struct xdp_buff));   /* xdp_buff shadow */

      shadow = addr;

      shadow->data = (void *)(uintptr_t)(GBPF_PKT_BASE + page_off(xdp->data));

      /* 1페이지니까 end/meta가 같은 페이지일 때만 rewrite */
      if (virt_to_page((void *)((unsigned long)xdp->data_end & PAGE_MASK)) == prog->aux->gbpf_pkt_page)
	shadow->data_end = (void *)(uintptr_t)(GBPF_PKT_BASE + page_off(xdp->data_end));

      if (xdp->data_meta &&
	  virt_to_page((void *)((unsigned long)xdp->data_meta & PAGE_MASK)) == prog->aux->gbpf_pkt_page)
	shadow->data_meta = (void *)(uintptr_t)(GBPF_PKT_BASE + page_off(xdp->data_meta));

      return (void *)(uintptr_t)GBPF_CTX_BASE; /* 너가 ctx를 놓기로 한 BPF-space VA */
    }

    addr = page_to_virt(prog->aux->gbpf_page);
    memcpy(addr, ctx, ctx_size);
    // ret = addr;
    ret = (void *)(uintptr_t)GBPF_CTX_BASE;

    pr_info("CTX ADDR = %px\n", addr);
    pr_info("CTX SIZE = %lu\n", ctx_size);

  }

  return ret;
}

#endif /* _LINUX_GBPF_H  */
