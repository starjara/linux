#ifndef _LINUX_GBPF_H
#define _LINUX_GBPF_H

#include <linux/types.h>
#include <linux/bpf.h>

struct page;

extern size_t gbpf_ctx_size_map[];

struct gbpf_ops {
  int (*create_pgd)(struct bpf_prog *prog);
  int (*map)(struct bpf_prog *prog);
  void (*destroy_pgtable)(struct bpf_prog *prog);
  u32 (*get_vmid)(void);
  void (*inc_vmid)(void);
  void (*dec_vmid)(void);
};

int gbpf_register_ops(const struct gbpf_ops *ops);
void gbpf_unregister_ops(const struct gbpf_ops *ops);

const struct gbpf_ops *pbpf_ops_get(void);

int gbpf_call_create_pgd(struct bpf_prog *prog);
int gbpf_call_map(struct bpf_prog *prog);
void gbpf_call_destroy_pgtable(struct bpf_prog *prog);
u32 gbpf_call_get_vmid(void);
void gbpf_call_inc_vmid(void);
void gbpf_call_dec_vmid(void);
static __always_inline void *gbpf_copy_ctx(const void *ctx, const struct bpf_prog *prog);

static __always_inline void *gbpf_copy_ctx(const void *ctx, const struct bpf_prog *prog)
{
  size_t ctx_size; 
  void *addr = NULL;
  void *ret = NULL;


  if(ctx) {
    ctx_size = gbpf_ctx_size_map[prog->type];
    if (ctx_size == 8)
      ctx_size = 64;
    addr = prog->aux->gbpf_page;
    memcpy(addr, ctx, ctx_size);
    // ret = addr;
    ret = (void *)(uintptr_t)0x80000000;
    pr_info("CTX ADDR = %p\n", addr);
    pr_info("CTX SIZE = %lld\n", ctx_size);
  }

  return ret;
}

#endif /* _LINUX_GBPF_H  */
