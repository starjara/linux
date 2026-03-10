#include <linux/kernel.h>
#include <linux/gbpf.h>
#include "gbpf_trampoline.h"

#define LOG_E pr_info("[gbpf_trampoline.c] Enter: %s\n", __func__)


const struct gbpf_helper_desc gbpf_helper_descs[] = {
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
  pr_info("\t%llx\n", arg);

  // In GBPF stack space 
  if (GBPF_CTX_BASE <= arg && arg <= GBPF_CTX_BASE + GBPF_PAGE_SIZE) {
    ret -= GBPF_CTX_BASE;
  }

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

	if (desc->arg_kind[0] == GBPF_ARG_GBPF_STACK)
		marshaled[0] = gbpf_from_gbpf_space_to_kernel(arg1);

	ret = gbpf_call_helper_generic(func_addr,
				       marshaled[0], marshaled[1],
				       marshaled[2], marshaled[3],
				       marshaled[4]);

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
  u64 target_id;
  u64 ret;
  //const struct gbpf_helper_desc *desc = NULL;

  LOG_E;

  call_target = gbpf_read_helper_meta(&target_id);

  pr_info("\tTarget Call: [%llu], %px\n", target_id,  (void *)call_target);
  pr_info("\tArgs : [%llx, %llx, %llx, %llx, %llx]\n", arg1, arg2, arg3, arg4, arg5);

  /*
  desc = gbpf_get_helper_desc(target_id);
  
  if (desc) {
    pr_info("\t\tWith desc\n");

    ret = gbpf_call_helper_desc(desc, call_target,  arg1, arg2, arg3, arg4, arg5);
  }
  else {
    pr_info("\t\tWithout desc\n");
    ret = gbpf_call_helper_generic(call_target, arg1, arg2, arg3, arg4, arg5); 
  }

  ret = gbpf_convert_helper_ret(desc, ret);
  
  */

  pr_info("[GBPF] Tramptest ret = 0x%llx\n", ret);
  
  return ret;
}
EXPORT_SYMBOL_GPL(gbpf_helper_call_trampoline);
