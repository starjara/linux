#include <linux/kernel.h>
#include <linux/filter.h>
#include <linux/gbpf.h>

//#define LOG_E pr_info("[gbpf_map_addr.c] Enter: %s\n", __func__)
#define LOG_E ;
//#define GBPF_DEBUG 1

int gbpf_init_prog_map_descs(struct bpf_prog *prog)
{
  u32 i;

  LOG_E;

  if (!prog || !prog->aux || !prog->aux->used_map_cnt)
    return 0;
  
  prog->aux->gaux->gbpf_maps = kcalloc(prog->aux->used_map_cnt,
				 sizeof(*prog->aux->gaux->gbpf_maps),
				 GFP_KERNEL);
  if (!prog->aux->gaux->gbpf_maps)
    return -ENOMEM;

#ifdef GBPF_DEBUG
  pr_info("[GBPF] init map descs: cnt=%u\n",
	  prog->aux->used_map_cnt);
#endif
  
  for (i = 0; i < prog->aux->used_map_cnt; i++) {
    struct bpf_map *map = prog->aux->used_maps[i];
    struct gbpf_map_desc *d = &prog->aux->gaux->gbpf_maps[i];
    int cpu;
    
    d->map = map;
    d->map_slot = i;
    
    d->percpu = map->map_type == BPF_MAP_TYPE_PERCPU_ARRAY ||
      map->map_type == BPF_MAP_TYPE_LRU_PERCPU_HASH ||
      map->map_type == BPF_MAP_TYPE_PERCPU_HASH;
    
#ifdef GBPF_DEBUG
    pr_info("[GBPF] map[%u]: type=%d percpu=%d map=%px\n",
	    i, map->map_type, d->percpu, map);
#endif
    
    if (!d->percpu) {
      d->base = map->gbpf_alloc_base;

#ifdef GBPF_DEBUG
			pr_info("[GBPF] map[%u] base=%px\n",
				i, (void *)d->base);
#endif
    } else {
      for_each_possible_cpu(cpu) {
	struct bpf_array *array = (struct bpf_array *)map;
	d->percpu_base[cpu] =
	  *per_cpu_ptr(array->pptrs, cpu);

#ifdef GBPF_DEBUG
	if (d->percpu_base[cpu])
	  pr_info("[GBPF] map[%u] cpu[%d] base=%px\n",
		  i, cpu,
		  (void *)d->percpu_base[cpu]);
#endif
      }
    }
  }
  
  return 0;
}

int gbpf_try_encode_kernel_map_ptr(u64 kptr, struct bpf_prog *prog, u64 *out)
{
  u32 i;

  LOG_E;

  if (!prog || !prog->aux || !prog->aux->gaux->gbpf_maps || !out)
    return -EINVAL;
  
#ifdef GBPF_DEBUG
	pr_info("[GBPF] encode try: kptr=%px\n", (void *)kptr);
#endif
  
  for (i = 0; i < prog->aux->used_map_cnt; i++) {
    struct gbpf_map_desc *d = &prog->aux->gaux->gbpf_maps[i];

#ifdef GBPF_DEBUG
    pr_info("[GBPF]  check map[%u] percpu=%d\n",
	    i, d->percpu);
#endif

    if (kptr == (u64)d->map) {
#ifdef GBPF_DEBUG
      pr_info("[GBPF]   MATCH map[%u] kptr : 0x%lx, map : %px\n",
	      i, kptr, d->map);
#endif
      *out = gbpf_encode_map_addr(d->map_slot, 0, 0);

      return 0;

    }
    
    if (!d->percpu) {

#ifdef GBPF_DEBUG
      pr_info("[GBPF]   range: [%px - %px), map : %px\n",
	      (void *)d->base,
	      (void *)(d->base + GBPF_MAP_WINDOW_SIZE),
	      d->map);
#endif
      
      if (kptr >= d->base &&
	  kptr < d->base + GBPF_MAP_WINDOW_SIZE) {

	u64 off = kptr - d->base;
	
	*out = gbpf_encode_map_addr(d->map_slot, 0,
				    off);
#ifdef GBPF_DEBUG
	pr_info("[GBPF]   MATCH map[%u] off=0x%llx -> gbpf=0x%llx\n",
		i, off, *out);
#endif
	
	if (kptr == d->map) {
#ifdef GBPF_DEBUG
	pr_info("[GBPF]   MATCH map[%u] off=0x%llx -> gbpf=0x%llx\n",
		i, off, *out);
#endif
	}
	
	return 0;
      }
    } else {
      int cpu;
      
      for_each_possible_cpu(cpu) {
	u64 base = d->percpu_base[cpu];
	
	if (!base)
	  continue;

#ifdef GBPF_DEBUG
	pr_info("[GBPF]   cpu[%d] range: [%px - %px), map : %px\n",
		cpu,
		(void *)base,
		(void *)(base + GBPF_CPU_WINDOW_SIZE), 
		d->map);
#endif
	
	if (kptr >= base &&
	    kptr < base + GBPF_CPU_WINDOW_SIZE) {

	  u64 off = kptr - base;
	  
	  *out = gbpf_encode_map_addr(d->map_slot,
				      cpu,
				      off);

#ifdef GBPF_DEBUG
	  pr_info("[GBPF]   MATCH map[%u] cpu[%d] off=0x%llx -> gbpf=0x%llx\n",
		  i, cpu, off, *out);
#endif


	  
	  
	  return 0;
	}
      }
    }
  }

  
#ifdef GBPF_DEBUG
  pr_info("[GBPF] encode FAIL: kptr=%px\n", (void *)kptr);
#endif
  
  return -ENOENT;
}
EXPORT_SYMBOL_GPL(gbpf_try_encode_kernel_map_ptr);
