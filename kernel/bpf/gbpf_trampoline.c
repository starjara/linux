#include <linux/kernel.h>
#include <linux/gbpf.h>
#include <linux/percpu.h>
#include <uapi/linux/bpf.h>
#include <linux/smp.h>
#include "gbpf_trampoline.h"

#define LOG_E pr_info("[gbpf_trampoline.c] Enter: %s\n", __func__)
//#define LOG_E ;
#define GBPF_DEBUG 1
//static DEFINE_PER_CPU(struct gbpf_helper_desc, gbpf_helper_fallback_desc);

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

static u8 gbpf_arg_kind_from_bpf_arg_type(enum bpf_arg_type arg_type);
static u8 gbpf_ret_kind_from_bpf_ret_type(enum bpf_return_type ret_type);

static bool gbpf_arg_needs_translation(u8 kind)
{
	return kind == GBPF_ARG_GBPF_STACK || kind == GBPF_ARG_PTR;
}

static bool gbpf_helper_uses_orig_ctx(const struct gbpf_helper_desc *desc)
{
	int i;

	if (!desc)
		return false;

	for (i = 0; i < desc->nr_args; i++) {
		if (desc->arg_kind[i] == GBPF_ARG_CTX)
			return true;
	}

	return false;
}

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

  LOG_E;
#ifdef GBPF_DEBUG
  pr_info("\tBPF to kernel : %lx\n", arg);
#endif

  if (arg == GBPF_CTX_BASE) {
    ret = m->ctx_base;
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
#ifdef GBPF_DEBUG
    pr_info("MAP PAGE\n");
#endif
    gbpf_decode_map_addr(ret, &gmap_addr_meta.map_slot, &gmap_addr_meta.cpu_slot, &gmap_addr_meta.off);
#ifdef GBPF_DEBUG
    pr_info("map addr meta - slot : %u, cpu : %u, off : %u\n", gmap_addr_meta.map_slot, gmap_addr_meta.cpu_slot, gmap_addr_meta.off);
#endif
    //ret -= GBPF_MAP_BASE;
    if (ret < GBPF_MAP_BASE)
      ret = m->map_base;
    else {
      ret = ret > GBPF_MAP_BASE ? ret - GBPF_MAP_BASE : GBPF_MAP_BASE - ret;
      ret += m->map_base;
    }
  }
  
#ifdef GBPF_DEBUG 
  pr_info("\tBPF to kernel : %lx\n", ret);
#endif
  
  return ret;
}

static u64 gbpf_call_helper_desc(const struct gbpf_helper_desc *desc, const struct gbpf_helper_meta *meta,
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
	//int nr_args = desc ? desc->nr_args : ARRAY_SIZE(marshaled);

	marshaled[0] = arg1;
	marshaled[1] = arg2;
	marshaled[2] = arg3;
	marshaled[3] = arg4;
	marshaled[4] = arg5;

	for (int i=0; i<5; i++) {
	  marshaled[i] = gbpf_from_gbpf_space_to_kernel(meta, marshaled[i]);
	}

	
	for (int i = 0; i < 1; i++) {
	  u8 kind = desc ? desc->arg_kind[i] : GBPF_ARG_UNUSED;
	  
	 // if (kind == GBPF_ARG_CTX) {
	 //   marshaled[i] = meta->orig_ctx;
	 //   continue;
	 // }
	  
	  if (gbpf_arg_needs_translation(kind))
	    marshaled[i] = gbpf_from_gbpf_space_to_kernel(meta, marshaled[i]);
	}
	

	if (gbpf_is_internal_skb_load_helper(func_addr)) {
	  marshaled[0] = meta->orig_ctx;
	}
	
  
	ret = gbpf_call_helper_generic(func_addr,
				       marshaled[0], marshaled[1],
				       marshaled[2], marshaled[3],
				       marshaled[4]);

	return ret;
}

static u64 gbpf_convert_helper_ret(const struct gbpf_helper_desc *desc, u64 ret, struct gbpf_helper_meta *m)
{
  LOG_E;
  
  if (!ret)
    return ret;

  if (ret >= 0xff60000000000000 && ret <= 0xff70000000000000 ) {
    struct bpf_map *map = (struct bpf_map *)m->map_base;
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
      pr_info("[tramp] percpu_off : 0x%lx\n", off);
      u64 off2 =  ret - (u64) *per_cpu_ptr(array->pptrs, cpu);
      pr_info("[tramp] percpu_off2 : 0x%lx\n", off2);
      //gbpf_call_map_ext(prog, map->gbpf_alloc_base, map->value_region.size, MAP);
      ret = gbpf_encode_map_addr(gmap_addr_meta.cpu_slot, cpu, off);
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
  const struct gbpf_helper_desc *desc = NULL;
  

  meta = gbpf_read_helper_meta();
  call_target = (u64)((u8 *)__bpf_call_base + (s32)meta.call_imm);

  LOG_E;
  
  //desc = gbpf_get_helper_desc((u32)meta.helper_id);

#ifdef GBPF_DEBUG
  if(desc)
    pr_info("Desc exist\n");
  else
    pr_info("Desc not found\n");
#endif
  
#ifdef GBPF_DEBUG
  pr_info("\tBPF_call_base : %px\n", (u8 *)__bpf_call_base);
  pr_info("\tTarget Call: %px\n", (void *)call_target);
  pr_info("\ttarget_imm : %d\n", (s32)meta.call_imm);
  pr_info("\tprog_type  : %llu\n", meta.prog_type);
  pr_info("\tArgs : [%llx, %llx, %llx, %llx, %llx]\n",
	  arg1, arg2, arg3, arg4, arg5);
#endif

  /*
  if (!desc)
    pr_warn("gbpf: unknown helper id %llu, call target=%px\n",
	    meta.helper_id, (void *)call_target);
  else if (gbpf_helper_uses_orig_ctx(desc) && !meta.orig_ctx)
    pr_warn("gbpf: helper %u expects kernel ctx but orig_ctx is missing\n",
	    desc->helper_id);
  */

  // ToDo : Save map ptr metadata and use it for return addr convert
  ret = gbpf_call_helper_desc(desc, &meta, call_target,
			      arg1, arg2, arg3, arg4, arg5);
  
#ifdef GBPF_DEBUG
  pr_info("[GBPF] Tramptest ret_before = 0x%lx\n", ret);
#endif

  ret = gbpf_convert_helper_ret(desc, ret, &meta);

#ifdef GBPF_DEBUG
  pr_info("[GBPF] Tramptest ret_after = 0x%lx\n", ret);
#endif

  
  return ret;
}
EXPORT_SYMBOL_GPL(gbpf_helper_call_trampoline);


/*
const struct gbpf_helper_desc gbpf_helper_descs[__BPF_FUNC_MAX_ID] = {
  [BPF_FUNC_unspec] = {
    .helper_id = BPF_FUNC_unspec,
    .name = "bpf_unspec",
    .nr_args = 0,
    .arg_kind = {
      GBPF_ARG_UNUSED,
      GBPF_ARG_UNUSED,
      GBPF_ARG_UNUSED,
      GBPF_ARG_UNUSED,
      GBPF_ARG_UNUSED,
    },
    .ret_kind = GBPF_RET_UNUSED,
  },
  [BPF_FUNC_ktime_get_ns] = {
    .helper_id = BPF_FUNC_ktime_get_ns,
    .name = "bpf_ktime_get_ns", 
    .nr_args = 5,
    .arg_kind = {
      GBPF_ARG_UNUSED,
      GBPF_ARG_UNUSED,
      GBPF_ARG_UNUSED,
      GBPF_ARG_UNUSED,
      GBPF_ARG_UNUSED,
    },
    .ret_kind = GBPF_RET_SCALAR,
  },
  [BPF_FUNC_trace_printk] = {
    .helper_id = BPF_FUNC_trace_printk,
    .name = "bpf_trace_printk",
    .nr_args = 5,
    .arg_kind = {
      GBPF_ARG_GBPF_STACK, 
      GBPF_ARG_SCALAR,  
      GBPF_ARG_SCALAR,
      GBPF_ARG_SCALAR,
      GBPF_ARG_SCALAR,
    },
    .ret_kind = GBPF_RET_SCALAR,
  },
  [BPF_FUNC_get_prandom_u32] = {
    .helper_id = BPF_FUNC_get_prandom_u32,
    .name = "bpf_get_prandom_u32",
    .nr_args = 5,
    .arg_kind = {
      GBPF_ARG_UNUSED,
      GBPF_ARG_UNUSED,
      GBPF_ARG_UNUSED,
      GBPF_ARG_UNUSED,
      GBPF_ARG_UNUSED,
    },
    .ret_kind = GBPF_RET_SCALAR,
  },
    [BPF_FUNC_map_lookup_elem] = {
    .helper_id = BPF_FUNC_map_lookup_elem,
    .name = "bpf_map_lookup_elem",
    .nr_args = 2,
    .arg_kind = {
      GBPF_ARG_MAP_PTR,
      GBPF_ARG_GBPF_STACK,
      GBPF_ARG_UNUSED,
      GBPF_ARG_UNUSED,
      GBPF_ARG_UNUSED,
    },
    .ret_kind = GBPF_RET_PTR_TO_MAP_VALUE,
  },
  [BPF_FUNC_map_update_elem] = {
    .helper_id = BPF_FUNC_map_update_elem,
    .name = "bpf_map_update_elem",
    .nr_args = 4,
    .arg_kind = {
      GBPF_ARG_PTR,
      GBPF_ARG_PTR,
      GBPF_ARG_PTR,
      GBPF_ARG_SCALAR,
      GBPF_ARG_UNUSED,
    },
    .ret_kind = GBPF_RET_SCALAR,
  },
  [BPF_FUNC_map_delete_elem] = {
    .helper_id = BPF_FUNC_map_delete_elem,
    .name = "bpf_map_delete_elem",
    .nr_args = 2,
    .arg_kind = {
      GBPF_ARG_PTR,
      GBPF_ARG_PTR,
      GBPF_ARG_UNUSED,
      GBPF_ARG_UNUSED,
      GBPF_ARG_UNUSED,
    },
    .ret_kind = GBPF_RET_SCALAR,
  },
  [BPF_FUNC_xdp_load_bytes] = {
    .helper_id = BPF_FUNC_xdp_load_bytes,
    .name = "bpf_xdp_load_bytes",
    .nr_args = 4,
    .arg_kind = {
      GBPF_ARG_CTX,
      GBPF_ARG_SCALAR,
      GBPF_ARG_PTR,
      GBPF_ARG_SCALAR,
      GBPF_ARG_UNUSED,
    },
    .ret_kind = GBPF_RET_SCALAR,
  },
  [BPF_FUNC_xdp_store_bytes] = {
    .helper_id = BPF_FUNC_xdp_store_bytes,
    .name = "bpf_xdp_store_bytes",
    .nr_args = 4,
    .arg_kind = {
      GBPF_ARG_CTX,
      GBPF_ARG_SCALAR,
      GBPF_ARG_PTR,
      GBPF_ARG_SCALAR,
      GBPF_ARG_UNUSED,
    },
    .ret_kind = GBPF_RET_SCALAR,
  },
  [BPF_FUNC_xdp_adjust_tail] = {
    .helper_id = BPF_FUNC_xdp_adjust_tail,
    .name      = "bpf_xdp_adjust_tail",
    .nr_args   = 2,
    .arg_kind = {
      GBPF_ARG_CTX,
      GBPF_ARG_SCALAR,
      GBPF_ARG_UNUSED,
      GBPF_ARG_UNUSED,
      GBPF_ARG_UNUSED,
    },
    .ret_kind = GBPF_RET_SCALAR,
  },
  [BPF_FUNC_skb_load_bytes] = {
    .helper_id = BPF_FUNC_skb_load_bytes,
    .name = "bpf_skb_load_bytes",
    .nr_args = 4,
    .arg_kind = {
      GBPF_ARG_CTX,
      GBPF_ARG_SCALAR,
      GBPF_ARG_PTR,
      GBPF_ARG_SCALAR,
      GBPF_ARG_UNUSED,
    },
    .ret_kind = GBPF_RET_SCALAR,
  },
  [BPF_FUNC_skb_store_bytes] = {
    .helper_id = BPF_FUNC_skb_store_bytes,
    .name = "bpf_skb_store_bytes",
    .nr_args = 5,
    .arg_kind = {
      GBPF_ARG_CTX,
      GBPF_ARG_SCALAR,
      GBPF_ARG_PTR,
      GBPF_ARG_SCALAR,
      GBPF_ARG_SCALAR,
    },
    .ret_kind = GBPF_RET_SCALAR,
  },
};

const struct gbpf_helper_desc *gbpf_get_helper_desc(u32 helper_id)
{
  	struct gbpf_helper_desc *desc;
	const struct bpf_func_proto *proto;
	u32 nr_args = 0;
	int i;

	LOG_E;

	if (helper_id >= ARRAY_SIZE(gbpf_helper_descs))
		return NULL;
	if (gbpf_helper_descs[helper_id].helper_id != helper_id)
		goto build_fallback;

	return &gbpf_helper_descs[helper_id];

build_fallback:
#ifdef GBPF_DEBUG
	pr_info("Build fall back\n");
#endif
	
	proto = bpf_base_func_proto(helper_id);
	if (!proto)
		return NULL;

	desc = this_cpu_ptr(&gbpf_helper_fallback_desc);
	memset(desc, 0, sizeof(*desc));
	desc->helper_id = helper_id;
	desc->ret_kind = gbpf_ret_kind_from_bpf_ret_type(proto->ret_type);

	for (i = 0; i < ARRAY_SIZE(desc->arg_kind); i++) {
		desc->arg_kind[i] = gbpf_arg_kind_from_bpf_arg_type(proto->arg_type[i]);
		if (desc->arg_kind[i] != GBPF_ARG_UNUSED)
			nr_args = i + 1;
	}
	desc->nr_args = nr_args;

	return desc;
}

static u32 gbpf_base_bpf_arg_type(enum bpf_arg_type arg_type)
{
	return arg_type & GENMASK(BPF_BASE_TYPE_BITS - 1, 0);
}

static u32 gbpf_base_bpf_ret_type(enum bpf_return_type ret_type)
{
	return ret_type & GENMASK(BPF_BASE_TYPE_BITS - 1, 0);
}

static u8 gbpf_arg_kind_from_bpf_arg_type(enum bpf_arg_type arg_type)
{
	switch (gbpf_base_bpf_arg_type(arg_type)) {
	case ARG_DONTCARE:
		return GBPF_ARG_UNUSED;
	case ARG_ANYTHING:
	case ARG_CONST_SIZE:
	case ARG_CONST_SIZE_OR_ZERO:
	case ARG_CONST_ALLOC_SIZE_OR_ZERO:
		return GBPF_ARG_SCALAR;
	case ARG_PTR_TO_CTX:
		return GBPF_ARG_CTX;
	case ARG_CONST_MAP_PTR:
	case ARG_PTR_TO_MAP_KEY:
	case ARG_PTR_TO_MAP_VALUE:
	case ARG_PTR_TO_MEM:
	case ARG_PTR_TO_SPIN_LOCK:
	case ARG_PTR_TO_INT:
	case ARG_PTR_TO_LONG:
	case ARG_PTR_TO_SOCKET:
	case ARG_PTR_TO_BTF_ID:
	case ARG_PTR_TO_RINGBUF_MEM:
	case ARG_PTR_TO_BTF_ID_SOCK_COMMON:
	case ARG_PTR_TO_PERCPU_BTF_ID:
	case ARG_PTR_TO_FUNC:
	case ARG_PTR_TO_STACK:
	case ARG_PTR_TO_TIMER:
	case ARG_PTR_TO_KPTR:
	case ARG_PTR_TO_DYNPTR:
		return GBPF_ARG_PTR;
	case ARG_PTR_TO_CONST_STR:
		return GBPF_ARG_GBPF_STACK;
	default:
		return GBPF_ARG_PTR;
	}
}

static u8 gbpf_ret_kind_from_bpf_ret_type(enum bpf_return_type ret_type)
{
	switch (gbpf_base_bpf_ret_type(ret_type)) {
	case RET_VOID:
		return GBPF_RET_UNUSED;
	case RET_PTR_TO_MAP_VALUE:
		return GBPF_RET_PTR_TO_MAP_VALUE;
	case RET_PTR_TO_MEM:
	case RET_PTR_TO_MEM_OR_BTF_ID:
	case RET_PTR_TO_BTF_ID:
	case RET_PTR_TO_SOCKET:
	case RET_PTR_TO_TCP_SOCK:
	case RET_PTR_TO_SOCK_COMMON:
		return GBPF_RET_PTR_TO_MEM;
	case RET_INTEGER:
	default:
		return GBPF_RET_SCALAR;
	}
}
*/

