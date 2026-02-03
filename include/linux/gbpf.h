#ifndef _LINUX_GBPF_H
#define _LINUX_GBPF_H

#include <linux/types.h>

struct bpf_prog;
struct page;

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

#endif /* _LINUX_GBPF_H  */
