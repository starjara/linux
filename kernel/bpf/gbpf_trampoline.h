#ifndef _GBPF_HELPERS_H
#define _GBPF_HELPERS_H

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/kernel.h>
#include <linux/filter.h>

enum gbpf_arg_kind {
  GBPF_ARG_UNUSED = 0,
  GBPF_ARG_SCALAR,
  GBPF_ARG_GBPF_STACK,
};

enum gbpf_ret_kind {
  GBPF_RET_SCALAR = 0,
  GBPF_RET_PTR_TO_MAP_VALUE,
  GBPF_RET_PTR_TO_MEM,
};

struct gbpf_helper_desc {
  u32 helper_id;
  const char *name;
  u8 nr_args;
  u8 arg_kind[5];
  u8 ret_kind;
};

typedef u64 (*gbpf_helper_fn_t)(u64, u64, u64, u64, u64);

extern const struct gbpf_helper_desc gbpf_helper_descs[];

// Descriptor table function prototypes
const struct gbpf_helper_desc *gbpf_get_helper_desc(u32 helper_id);

// Prog type and call target parser
static __always_inline u64 gbpf_read_helper_prog_type(void)
{
  u64 prog_type;

  asm volatile("mv %0, s10" : "=r"(prog_type));
  return prog_type;
}

static __always_inline u64 gbpf_read_helper_call_target(void)
{
  u64 call_target;

  asm volatile("mv %0, s10" : "=r"(call_target));
  return call_target;
}

static __always_inline u64 gbpf_read_helper_meta(u64 *target_id)
{
  u64 call_target;
  u64 tmp_target_id;

  asm volatile (
		"mv %0, s10\n\t"
		"mv %1, s11\n\t"
		: "=r"(tmp_target_id), "=r"(call_target)
		:
		:);
  
  *target_id = tmp_target_id;
  return call_target;
}

#endif /* _GBPF_HELPERS_H */
