#include <linux/kernel.h>
#include <linux/gbpf.h>
#include <uapi/linux/bpf.h>
#include "gbpf_trampoline.h"

#define LOG_E pr_info("[gbpf_trampoline.c] Enter: %s\n", __func__)

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
      GBPF_ARG_GBPF_STACK, /* fmt */
      GBPF_ARG_SCALAR,  /* fmt_size */
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
      GBPF_ARG_PTR,
      GBPF_ARG_PTR,
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
  if (helper_id >= ARRAY_SIZE(gbpf_helper_descs))
    return NULL;
  if (gbpf_helper_descs[helper_id].helper_id != helper_id)
    return NULL;
  
  return &gbpf_helper_descs[helper_id];
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
  pr_info("\tBPF to kernel : %llx\n", arg);
  
  if (arg == GBPF_CTX_BASE) {
    ret = m->orig_ctx;
  }
  else if (GBPF_CTX_BASE <= arg && arg < GBPF_CTX_BASE + GBPF_PAGE_SIZE) {
    pr_info("CTX PAGE\n");
    ret -= GBPF_CTX_BASE;
    ret += m->ctx_base;
  } else if (GBPF_PKT_BASE <= arg && arg < GBPF_PKT_BASE + GBPF_PAGE_SIZE) {
    pr_info("PKT PAGE\n");
    ret -= GBPF_PKT_BASE;
    ret += m->pkt_base;
  } else if (GBPF_MAP_BASE <= arg && arg < GBPF_MAP_BASE + GBPF_PAGE_SIZE) {
    pr_info("MAP PAGE\n");
    ret -= GBPF_MAP_BASE;
    ret += m->map_base;
  }
  
  pr_info("\tBPF to kernel : %llx\n", ret);
  
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

	marshaled[0] = arg1;
	marshaled[1] = arg2;
	marshaled[2] = arg3;
	marshaled[3] = arg4;
	marshaled[4] = arg5;

	/*
	for (int i=0; i<5; i++) {
	  marshaled[i] = gbpf_from_gbpf_space_to_kernel(meta, marshaled[i]);
	}
	*/
	for (int i = 0; i < 5; i++) {
	  u8 kind = desc ? desc->arg_kind[i] : GBPF_ARG_UNUSED;
	  
	  if (kind == GBPF_ARG_CTX) {
	    marshaled[i] = meta->orig_ctx;
	    continue;
	  }
	  
	  if (kind == GBPF_ARG_GBPF_STACK || kind == GBPF_ARG_PTR)
	    marshaled[i] = gbpf_from_gbpf_space_to_kernel(meta, marshaled[i]);
	}



	ret = gbpf_call_helper_generic(func_addr,
				       marshaled[0], marshaled[1],
				       marshaled[2], marshaled[3],
				       marshaled[4]);

	return ret;
}

static u64 gbpf_convert_helper_ret(const struct gbpf_helper_desc *desc, u64 ret)
{
  if (!ret || !desc)
    return ret;

  
  switch (desc->ret_kind) {
  case GBPF_RET_SCALAR:
    return ret;
    
  case GBPF_RET_PTR_TO_MAP_VALUE:
    /* TODO: kernel ptr -> BPF-space ptr 변환 */
    return ret;
    
  case GBPF_RET_PTR_TO_MEM:
    /* TODO: 필요하면 나중에 변환 */
    return ret;
    
  default:
    return ret;
  }
}

noinline u64 gbpf_helper_call_trampoline(u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5)
{
  struct gbpf_helper_meta meta;
  u64 call_target;
  u64 ret;
  const struct gbpf_helper_desc *desc = NULL;

  LOG_E;

  meta = gbpf_read_helper_meta();
  call_target = (u64)((u8 *)__bpf_call_base + (s32)meta.call_imm);
  desc = gbpf_get_helper_desc((u32)meta.helper_id);
  
  pr_info("\tBPF_call_base : %px\n", (u8 *)__bpf_call_base);
  pr_info("\tTarget Call: %px\n", (void *)call_target);
  pr_info("\ttarget_imm : %d\n", (s32)meta.call_imm);
  pr_info("\thelper_id  : %llu\n", meta.helper_id);
  pr_info("\tArgs : [%llx, %llx, %llx, %llx, %llx]\n",
	  arg1, arg2, arg3, arg4, arg5);

  if (!desc)
    pr_warn("gbpf: unknown helper id %llu, call target=%px\n",
	    meta.helper_id, (void *)call_target);

  ret = gbpf_call_helper_desc(desc, &meta, call_target,
			      arg1, arg2, arg3, arg4, arg5);
  ret = gbpf_convert_helper_ret(desc, ret);

  pr_info("[GBPF] Tramptest ret = 0x%llx\n", ret);
  
  return ret;
}
EXPORT_SYMBOL_GPL(gbpf_helper_call_trampoline);
