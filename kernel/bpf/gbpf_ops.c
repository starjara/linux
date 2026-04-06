#include <linux/errno.h>
#include <linux/export.h>
#include <linux/srcu.h>
#include <linux/gbpf.h>

static const struct gbpf_ops *gbpf_ops_ptr;
DEFINE_SRCU(gbpf_srcu);

const struct gbpf_ops *gbpf_ops_get(void)
{
  return gbpf_ops_ptr;
}
EXPORT_SYMBOL_GPL(gbpf_ops_get);

int gbpf_register_ops(const struct gbpf_ops *ops)
{
  if (!ops)
    return -EINVAL;

  if (gbpf_ops_ptr)
    return -EBUSY;

  gbpf_ops_ptr = ops;
  return 0;
}
EXPORT_SYMBOL_GPL(gbpf_register_ops);

void gbpf_unregister_ops(const struct gbpf_ops *ops)
{
  if (!ops)
    return ;

  gbpf_ops_ptr = NULL;

  synchronize_srcu(&gbpf_srcu);
}
EXPORT_SYMBOL_GPL(gbpf_unregister_ops);

int gbpf_call_check_module(void)
{
  const struct gbpf_ops *ops;
  int idx, ret = 0;

  idx = srcu_read_lock(&gbpf_srcu);
  ops = gbpf_ops_ptr;
  
  if (ops && ops->check_module)
    ret = ops->check_module();
  
  srcu_read_unlock(&gbpf_srcu, idx);
  return ret;
}
EXPORT_SYMBOL_GPL(gbpf_call_check_module);

int gbpf_call_create_pgd(struct bpf_prog *prog)
{
    const struct gbpf_ops *ops;
    int idx, ret = 0;

    idx = srcu_read_lock(&gbpf_srcu);
    ops = gbpf_ops_ptr;

    if (ops && ops->create_pgd)
      ret = ops->create_pgd(prog);

    srcu_read_unlock(&gbpf_srcu, idx);
    return ret;
}
EXPORT_SYMBOL_GPL(gbpf_call_create_pgd);

int gbpf_call_map(struct bpf_prog *prog)
{
    const struct gbpf_ops *ops;
    int idx, ret = 0;

    idx = srcu_read_lock(&gbpf_srcu);
    ops = gbpf_ops_ptr;

    if (ops && ops->map)
      ret = ops->map(prog);

    srcu_read_unlock(&gbpf_srcu, idx);
    return ret;

}
EXPORT_SYMBOL_GPL(gbpf_call_map);

int gbpf_call_map_ext(const struct bpf_prog *prog, const void *kaddr, size_t len, enum GBPF_MAP_TYPE type, int map_num, int cpu)
{
    const struct gbpf_ops *ops;
    int idx, ret = 0;

    idx = srcu_read_lock(&gbpf_srcu);
    ops = gbpf_ops_ptr;

    if (ops && ops->map_ext)
      ret = ops->map_ext(prog, kaddr, len, type, map_num, cpu);

    srcu_read_unlock(&gbpf_srcu, idx);
    return ret;

}
EXPORT_SYMBOL_GPL(gbpf_call_map_ext);

void gbpf_call_destroy_pgtable(struct bpf_prog *prog)
{
    const struct gbpf_ops *ops;
    int idx = 0;

    idx = srcu_read_lock(&gbpf_srcu);
    ops = gbpf_ops_ptr;

    if (ops && ops->destroy_pgtable)
      ops->destroy_pgtable(prog);

    srcu_read_unlock(&gbpf_srcu, idx);
    return ;

}
EXPORT_SYMBOL_GPL(gbpf_call_destroy_pgtable);

u32 gbpf_call_get_vmid(void)
{
    const struct gbpf_ops *ops;
    int idx, ret = 0;

    idx = srcu_read_lock(&gbpf_srcu);
    ops = gbpf_ops_ptr;

    if (ops && ops->get_vmid)
      ret = ops->get_vmid();

    srcu_read_unlock(&gbpf_srcu, idx);
    return ret;

}
EXPORT_SYMBOL_GPL(gbpf_call_get_vmid);



/*
int gbpf_call_map_page(struct bpf_prog *prog, unsigned int level, unsigned long vaddr)
{
    const struct gbpf_ops *ops;
    int idx, ret = 0;

    idx = srcu_read_lock(&gbpf_srcu);
    ops = gbpf_ops_ptr;

    if (ops && ops->map_page)
        ret = ops->map_page(prog, vaddr, page);

    srcu_read_unlock(&gbpf_srcu, idx);
    return ret;
}
EXPORT_SYMBOL_GPL(gbpf_call_map_page);
*/
