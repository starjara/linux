#include <linux/kernel.h>
#include <linux/gbpf.h>
#include <uapi/linux/bpf.h>
#include "gbpf_trampoline.h"

#define LOG_E pr_info("[gbpf_trampoline.c] Enter: %s\n", __func__)

u64 ctx_base;


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
};

const struct gbpf_helper_desc *gbpf_get_helper_desc(u32 helper_id)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(gbpf_helper_descs); i++) {
		if (gbpf_helper_descs[i].helper_id == helper_id)
			return &gbpf_helper_descs[i];
	}
	return NULL;
}

static __always_inline u64 gbpf_translate_fmt_str_ptr(u64 bpf_ptr)
{
	/*
	 * TODO:
	 * 네 BPF-space -> kernel-readable VA 변환 붙일 자리
	 *
	 * 지금은 bring-up이니까 일단 identity로 둠
	 */
	return bpf_ptr;
}

static u64 gbpf_call_helper_generic(u64 call_target,
			 u64 arg1, u64 arg2, u64 arg3,
			 u64 arg4, u64 arg5)
{
	gbpf_helper_fn_t fn;

	fn = (gbpf_helper_fn_t)(unsigned long)call_target;
	return fn(arg1, arg2, arg3, arg4, arg5);
}


static u64 gbpf_from_gbpf_space_to_kernel(u64 arg)
{
  u64 ret = arg;
  
  LOG_E;
  pr_info("\tBPF to kernel : %llx\n", arg);

  // In GBPF stack space 
  if (GBPF_CTX_BASE <= arg && arg <= GBPF_CTX_BASE + GBPF_PAGE_SIZE) {
    ret -= GBPF_CTX_BASE;
    ret += ctx_base;
  }
  // In GBPF ptk space 
  else if (GBPF_PKT_BASE <= arg && arg <= GBPF_PKT_BASE + GBPF_PAGE_SIZE) {
    ret -= GBPF_PKT_BASE;
    ret += ctx_base;
  }
  // In GBPF map space
  else if (GBPF_MAP_BASE <= arg && arg <= GBPF_MAP_BASE + GBPF_PAGE_SIZE) {
    ret -= GBPF_MAP_BASE;
    ret += ctx_base;
  }

  pr_info("\tBPF to kernel : %llx\n", ret);

  return ret;
}

static u64 gbpf_call_helper_desc(const struct gbpf_helper_desc *desc, u64 func_addr,
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

	for (int i=0; i<5; i++) {
	    marshaled[i] = gbpf_from_gbpf_space_to_kernel(marshaled[i]);
	}

	/*
	ret = gbpf_call_helper_generic(func_addr,
				       marshaled[0], marshaled[1],
				       marshaled[2], marshaled[3],
				       marshaled[4]);
	*/

	return ret;
}

static u64 gbpf_convert_helper_ret(const struct gbpf_helper_desc *desc, u64 ret)
{
	if (!ret)
		return 0;

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
  u64 call_target;
  u64 ret;
  const struct gbpf_helper_desc *desc = NULL;

  LOG_E;

  // Get target index
  call_target = gbpf_read_helper_meta(&ctx_base);

  pr_info("\tTarget Call: [0x%llx], %px\n", ctx_base,  (void *)call_target);
  pr_info("\tArgs : [%llx, %llx, %llx, %llx, %llx]\n", arg1, arg2, arg3, arg4, arg5);

  pr_info("\ttarget_imm : %lx\n", (s32)call_target);
  
  pr_info("\tBPF_call_base : %px\n", (u8 *)__bpf_call_base);
  call_target = (u64)((u8 *)__bpf_call_base + call_target);
  
  pr_info("\tBPF_call_base : %px\n", call_target);
  pr_info("Func id printk: %lx\n",  BPF_FUNC_ktime_get_ns);
  pr_info("Func id printk: %lx\n", BPF_FUNC_trace_printk);
  pr_info("Func id printk: %lx\n", BPF_FUNC_get_prandom_u32);

  ret = gbpf_call_helper_desc(NULL, call_target,  arg1, arg2, arg3, arg4, arg5);
 
  ret = gbpf_convert_helper_ret(NULL, ret);
  

  pr_info("[GBPF] Tramptest ret = 0x%llx\n", ret);
  
  return ret;
}
EXPORT_SYMBOL_GPL(gbpf_helper_call_trampoline);
