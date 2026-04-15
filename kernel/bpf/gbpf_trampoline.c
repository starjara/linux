#include <linux/kernel.h>
#include <linux/gbpf.h>
#include <linux/percpu.h>
#include <uapi/linux/bpf.h>
#include <linux/smp.h>
#include "gbpf_trampoline.h"

//#define LOG_E pr_info("[gbpf_trampoline.c] Enter: %s\n", __func__)
#define LOG_E ;
#define GBPF_DEBUG 1

/* net/core/filter.c 쪽 internal helper들 */
extern u64 bpf_skb_load_helper_8_no_cache(const struct sk_buff *skb, u64 off);
extern u64 bpf_skb_load_helper_16_no_cache(const struct sk_buff *skb, u64 off);
extern u64 bpf_skb_load_helper_32_no_cache(const struct sk_buff *skb, u64 off);

extern u64 bpf_skb_load_helper_8(const struct sk_buff *skb, u64 off,
                                 const void *data, u64 len);
extern u64 bpf_skb_load_helper_16(const struct sk_buff *skb, u64 off,
                                  const void *data, u64 len);
extern u64 bpf_skb_load_helper_32(const struct sk_buff *skb, u64 off,
                                  const void *data, u64 len);
extern u64 bpf_xdp_adjust_tail(struct xdp_buff *xdp, int offset);

static __always_inline bool gbpf_is_internal_skb_load_helper(u64 target)
{
    return target == (u64)(unsigned long)&bpf_skb_load_helper_8_no_cache  ||
           target == (u64)(unsigned long)&bpf_skb_load_helper_16_no_cache ||
           target == (u64)(unsigned long)&bpf_skb_load_helper_32_no_cache ||
           target == (u64)(unsigned long)&bpf_skb_load_helper_8           ||
           target == (u64)(unsigned long)&bpf_skb_load_helper_16          ||
           target == (u64)(unsigned long)&bpf_skb_load_helper_32;
}

/////////////////////////////// Internal helper fast path End

typedef struct map_addr_meta {
  u32 map_slot;
  u32 cpu_slot;
  u32 off;
  bool valid;
} map_addr_meta;

static inline u64 gbpf_from_gbpf_space_to_kernel(const struct gbpf_aux *gaux, u64 arg, map_addr_meta *meta, u64 target)
{
  u64 ret = arg;

  struct gbpf_map_desc *map_desc;
  
  LOG_E;
#ifdef GBPF_DEBUG
  pr_info("\tBefore BPF to kernel : %lx\n", arg);
#endif

  if(!arg)
    return arg;

  if (arg == GBPF_CTX_BASE) {
    if(target == (u64)bpf_xdp_adjust_tail)
      ret = page_to_virt(gaux->gbpf_page);
    else 
      ret = gaux->orig_ctx;
  }
  else if (GBPF_CTX_BASE <= arg && arg < GBPF_CTX_BASE + GBPF_PAGE_SIZE) {
#ifdef GBPF_DEBUG
    pr_info("CTX PAGE\n");
#endif
    ret -= GBPF_CTX_BASE;
    ret += (u64)page_to_virt(gaux->gbpf_page);
  } else if (GBPF_PKT_BASE <= arg && arg < GBPF_PKT_BASE + GBPF_PAGE_SIZE) {
#ifdef GBPF_DEBUG
    pr_info("PKT PAGE\n");
#endif
    ret -= GBPF_PKT_BASE;
    ret += (u64)gaux->pkt_page;
  } else if (GBPF_MAP_BASE - 0x1000 <= arg && arg < GBPF_MAP_BASE + GBPF_PAGE_SIZE) {
    map_desc = (struct gbpf_map_desc *)gaux->gbpf_maps;
#ifdef GBPF_DEBUG
    pr_info("MAP PAGE\n");
#endif
    if (!meta->valid) {
      gbpf_decode_map_addr(ret, &meta->map_slot, &meta->cpu_slot, &meta->off);
      meta->valid = true;
    }
    struct gbpf_map_desc *d = &map_desc[meta->map_slot];
#ifdef GBPF_DEBUG
    pr_info("map addr meta - slot : %u, cpu : %u, off : %u\n",
	    meta->map_slot, meta->cpu_slot, meta->off);
    pr_info("[GBPF] map[%u] base=%px\n", meta->map_slot, (void *)d->base);
#endif
    if (ret < GBPF_MAP_BASE)
      ret = d->map;
    else {
      ret = ret > GBPF_MAP_BASE ? ret - GBPF_MAP_BASE : GBPF_MAP_BASE - ret;
      ret += d->map;
    }
  }
  
#ifdef GBPF_DEBUG 
  pr_info("\tAfter BPF to kernel : %lx\n", ret);
#endif
  
  return ret;
}

static u64 gbpf_call_helper_generic(struct gbpf_aux *gaux, u64 call_target,
			 u64 arg1, u64 arg2, u64 arg3,
				    u64 arg4, u64 arg5,
				    map_addr_meta *meta)
{
  gbpf_helper_fn_t	fn;
  u64			ret;
  
  LOG_E;
	
#ifdef GBPF_DEBUG
  pr_info("Orig_ctx : 0x%lx", gaux->orig_ctx); 
#endif
	
  arg1 = gbpf_from_gbpf_space_to_kernel(gaux, arg1, meta, call_target);
  arg2 = gbpf_from_gbpf_space_to_kernel(gaux, arg2, meta, call_target);
  arg3 = gbpf_from_gbpf_space_to_kernel(gaux, arg3, meta, call_target);
  arg4 = gbpf_from_gbpf_space_to_kernel(gaux, arg4, meta, call_target);
  arg5 = gbpf_from_gbpf_space_to_kernel(gaux, arg5, meta, call_target);
	
#ifdef GBPF_DEBUG
  pr_info("Arg marshaling done\n");
#endif

  fn = (gbpf_helper_fn_t)(unsigned long)call_target;
  return fn(arg1, arg2, arg3, arg4, arg5);
}



static u64 gbpf_convert_helper_ret(u64 ret, struct gbpf_aux *gaux, const map_addr_meta *meta)
{
  LOG_E;
  
  if (!ret)
    return ret;

  if (virt_addr_valid(ret)) {
    struct gbpf_map_desc *map_desc = (struct gbpf_map_desc *)gaux->gbpf_maps;
    struct gbpf_map_desc *d = &map_desc[meta->map_slot];
    struct bpf_map *map = (struct bpf_map *)d->map;
    u64 elem = (u64)map->gbpf_alloc_base;
    u64 off;
    
#ifdef GBPF_DEBUG
    pr_info("[tramp] gbpf_alloc_base : 0x%lx\n", elem);
#endif
    if (map->map_type == BPF_MAP_TYPE_PERCPU_ARRAY) {
      struct bpf_array *array = (struct bpf_array *)map;
      u64 cpu_base = (u64)*per_cpu_ptr(array->pptrs, meta->cpu_slot);

      if (ret < cpu_base)
	return ret;

      off = ret - cpu_base;
      
      if (off >= GBPF_CPU_WINDOW_SIZE)
	return ret;

#ifdef GBPF_DEBUG
      pr_info("[tramp] percpu_off : 0x%lx\n", off);
#endif
      
      ret = gbpf_encode_map_addr(meta->map_slot, meta->cpu_slot, off);
    }
    else {
      off = ret - elem;
#ifdef GBPF_DEBUG
      pr_info("[tramp] off : 0x%lx\n", off);
#endif
      ret = GBPF_MAP_BASE + off;
    }
  }

  return ret;
 
}

noinline u64 gbpf_helper_call_trampoline(u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5)
{
  struct gbpf_aux *gaux;
  map_addr_meta meta = {};
  u64 call_target;
  u64 imm;
  u64 ret;

  imm = gbpf_read_gaux(&gaux);
  call_target = (u64)((u8 *)__bpf_call_base + (s32)imm);

  LOG_E;
  
#ifdef GBPF_DEBUG
  pr_info("\tBPF_call_base : %px\n", (u8 *)__bpf_call_base);
  pr_info("\tTarget Call: %px\n", (void *)call_target);
  pr_info("\ttarget_imm : %d\n", (s32)imm);
  pr_info("gaux : %px\n", gaux);
  pr_info("\tArgs : [%llx, %llx, %llx, %llx, %llx]\n",
	  arg1, arg2, arg3, arg4, arg5);
#endif

  ret = gbpf_call_helper_generic(gaux, call_target,
				 arg1, arg2, arg3, arg4, arg5, &meta);
  
#ifdef GBPF_DEBUG
  pr_info("[GBPF] Tramptest ret_before = 0x%lx\n", ret);
#endif

  ret = gbpf_convert_helper_ret(ret, gaux, &meta);

#ifdef GBPF_DEBUG
  pr_info("[GBPF] Tramptest ret_after = 0x%lx\n", ret);
#endif

  
  return ret;
}
EXPORT_SYMBOL_GPL(gbpf_helper_call_trampoline);

