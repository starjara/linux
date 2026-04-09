#include <linux/kernel.h>
#include <linux/gbpf.h>
#include <linux/percpu.h>
#include <uapi/linux/bpf.h>
#include <linux/smp.h>
#include "gbpf_trampoline.h"

#define LOG_E pr_info("[gbpf_trampoline.c] Enter: %s\n", __func__)
//#define LOG_E ;
#define GBPF_DEBUG 1

typedef struct map_addr_meta {
  u32 map_slot;
  u32 cpu_slot;
  u32 off;
} map_addr_meta;

map_addr_meta gmap_addr_meta;


/////////////////////////////// Internal helper fast path
#include <linux/filter.h>
#include <net/sock.h>
#include <linux/skbuff.h>

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

static u64 gbpf_call_helper_generic(u64 call_target,
			 u64 arg1, u64 arg2, u64 arg3,
			 u64 arg4, u64 arg5)
{
	gbpf_helper_fn_t fn;

	fn = (gbpf_helper_fn_t)(unsigned long)call_target;
	return fn(arg1, arg2, arg3, arg4, arg5);
}

static u64 gbpf_from_gbpf_space_to_kernel(const struct gbpf_helper_meta *m, u64 arg)
{
  u64 ret = arg;

  struct gbpf_map_desc *map_desc;
  
  LOG_E;
#ifdef GBPF_DEBUG
  pr_info("\tBPF to kernel : %lx\n", arg);
#endif

  if (arg == GBPF_CTX_BASE) {
    ret = m->orig_ctx;
  }
  else if (GBPF_CTX_BASE <= arg && arg < GBPF_CTX_BASE + GBPF_PAGE_SIZE) {
#ifdef GBPF_DEBUG
    pr_info("CTX PAGE\n");
#endif
    ret -= GBPF_CTX_BASE;
    ret += m->ctx_base;
  } else if (GBPF_PKT_BASE <= arg && arg < GBPF_PKT_BASE + GBPF_PAGE_SIZE) {
#ifdef GBPF_DEBUG
    pr_info("PKT PAGE\n");
#endif
    ret -= GBPF_PKT_BASE;
    ret += m->pkt_base;
  } else if (GBPF_MAP_BASE - 0x1000 <= arg && arg < GBPF_MAP_BASE + GBPF_PAGE_SIZE) {
    map_desc = (struct gbpf_map_desc *)m->map_desc_base;
#ifdef GBPF_DEBUG
    pr_info("MAP PAGE\n");
#endif
    gbpf_decode_map_addr(ret, &gmap_addr_meta.map_slot, &gmap_addr_meta.cpu_slot, &gmap_addr_meta.off);
    struct gbpf_map_desc *d = &map_desc[gmap_addr_meta.map_slot];
#ifdef GBPF_DEBUG
    pr_info("map addr meta - slot : %u, cpu : %u, off : %u\n", gmap_addr_meta.map_slot, gmap_addr_meta.cpu_slot, gmap_addr_meta.off);
    pr_info("[GBPF] map[%u] base=%px\n",
	    gmap_addr_meta.map_slot, (void *)d->base);
#endif
    //ret -= GBPF_MAP_BASE;
    if (ret < GBPF_MAP_BASE)
      ret = d->map;
    else {
      ret = ret > GBPF_MAP_BASE ? ret - GBPF_MAP_BASE : GBPF_MAP_BASE - ret;
      ret += d->map;
    }
  }
  
#ifdef GBPF_DEBUG 
  pr_info("\tBPF to kernel : %lx\n", ret);
#endif
  
  return ret;
}

static u64 gbpf_call_helper_desc(const struct gbpf_helper_meta *meta,
				 u64 func_addr,
				 u64 arg1, u64 arg2, u64 arg3,
				 u64 arg4, u64 arg5)
{
	u64 marshaled[5];
	u64 ret;

	LOG_E;
	
#ifdef GBPF_DEBUG
	pr_info("Orig_ctx : 0x%lx", meta->orig_ctx); 
#endif
	
	marshaled[0] = arg1;
	marshaled[1] = arg2;
	marshaled[2] = arg3;
	marshaled[3] = arg4;
	marshaled[4] = arg5;

	for (int i=0; i<5; i++) {
	  marshaled[i] = gbpf_from_gbpf_space_to_kernel(meta, marshaled[i]);
	}

	if (gbpf_is_internal_skb_load_helper(func_addr)) {
	  marshaled[0] = meta->orig_ctx;
	}
	
#ifdef GBPF_DEBUG
	pr_info("Arg marshaling done\n");
#endif
  
	ret = gbpf_call_helper_generic(func_addr,
				       marshaled[0], marshaled[1],
				       marshaled[2], marshaled[3],
				       marshaled[4]);

	return ret;
}

static u64 gbpf_convert_helper_ret(u64 ret, struct gbpf_helper_meta *m)
{
  LOG_E;
  
  if (!ret)
    return ret;

  if (ret >= 0xffffaf8000000000 && ret <= 0xffffaf9000000000) {
    //struct bpf_map *map = (struct bpf_map *)m->map_base;
    struct gbpf_map_desc *map_desc = (struct gbpf_map_desc *)m->map_desc_base;
    struct gbpf_map_desc *d = &map_desc[gmap_addr_meta.map_slot];
    struct bpf_map *map = (struct bpf_map *)d->map;
    u64 elem = (u64)map->gbpf_alloc_base;
    u64 off = ret - elem;
    
#ifdef GBPF_DEBUG
    //pr_info("[tramp] Tramptest ret_before = [0x%lx] %d\n", ret, *(u32 *)ret);
    pr_info("[tramp] gbpf_alloc_base : 0x%lx\n", elem);
    pr_info("[tramp] off : 0x%lx\n", off);
#endif
    if (map->map_type == BPF_MAP_TYPE_PERCPU_ARRAY) {
      u32 cpu = raw_smp_processor_id();
      struct bpf_array *array = (struct bpf_array *)map;
      off = off % PAGE_SIZE;
#ifdef GBPF_DEBUG
      pr_info("[tramp] percpu_off : 0x%lx\n", off);
#endif
      u64 off2 =  ret - (u64) *per_cpu_ptr(array->pptrs, cpu);
#ifdef GBPF_DEBUG
      pr_info("[tramp] percpu_off2 : 0x%lx\n", off2);
#endif
      ret = gbpf_encode_map_addr(gmap_addr_meta.map_slot, gmap_addr_meta.cpu_slot, off);
    }
    else {
      ret = GBPF_MAP_BASE + off;
    }
  }

  return ret;
 
}

noinline u64 gbpf_helper_call_trampoline(u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5)
{
  struct gbpf_helper_meta meta;
  u64 call_target;
  u64 ret;

  meta = gbpf_read_helper_meta();
  call_target = (u64)((u8 *)__bpf_call_base + (s32)meta.call_imm);

  LOG_E;
  
#ifdef GBPF_DEBUG
  pr_info("\tBPF_call_base : %px\n", (u8 *)__bpf_call_base);
  pr_info("\tTarget Call: %px\n", (void *)call_target);
  pr_info("\ttarget_imm : %d\n", (s32)meta.call_imm);
  pr_info("\tprog_type  : %llu\n", meta.prog_type);
  pr_info("\tArgs : [%llx, %llx, %llx, %llx, %llx]\n",
	  arg1, arg2, arg3, arg4, arg5);
#endif


  // ToDo : Save map ptr metadata and use it for return addr convert
  ret = gbpf_call_helper_desc(&meta, call_target,
			      arg1, arg2, arg3, arg4, arg5);
  
#ifdef GBPF_DEBUG
  pr_info("[GBPF] Tramptest ret_before = 0x%lx\n", ret);
#endif

  ret = gbpf_convert_helper_ret(ret, &meta);

#ifdef GBPF_DEBUG
  pr_info("[GBPF] Tramptest ret_after = 0x%lx\n", ret);
#endif

  
  return ret;
}
EXPORT_SYMBOL_GPL(gbpf_helper_call_trampoline);

