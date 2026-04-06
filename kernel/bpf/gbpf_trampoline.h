#ifndef _GBPF_HELPERS_H
#define _GBPF_HELPERS_H

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/kernel.h>
#include <linux/filter.h>

enum gbpf_arg_kind {
  GBPF_ARG_UNUSED = 0,
  GBPF_ARG_SCALAR,
  GBPF_ARG_PTR,
  GBPF_ARG_PKT_PTR,
  GBPF_ARG_MAP_PTR,
  GBPF_ARG_CTX,
  GBPF_ARG_GBPF_STACK,
};

enum gbpf_ret_kind {
  GBPF_RET_UNUSED = 0,
  GBPF_RET_SCALAR,
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



extern struct bpf_func_proto *gbpf_proto_table[][256];

/* gbpf_trampoline.h */

struct gbpf_helper_meta {
  /* Kernel aliases for GBPF virtual regions. */
  u64 ctx_base;
  u64 pkt_base;
  u64 map_base;
  /* Original helper ID preserved by verifier in insn->off. */
  u64 prog_type;
  /* __bpf_call_base-relative call target offset. */
  u64 call_imm;
  /* Original kernel ctx pointer for ctx-dereferencing helpers. */
  u64 orig_ctx;

};

typedef u64 (*gbpf_helper_fn_t)(u64, u64, u64, u64, u64);

extern const struct gbpf_helper_desc gbpf_helper_descs[];

// Descriptor table function prototypes
//const struct gbpf_helper_desc *gbpf_get_helper_desc(u32 helper_id);

static __always_inline struct gbpf_helper_meta gbpf_read_helper_meta(void)
{
  struct gbpf_helper_meta m;
  u64 fp;

  asm volatile (
		"mv %0, s10\n\t"
		"mv %1, s11\n\t"
		: "=r"(fp), "=r"(m.call_imm)
		:
		:);

  m.ctx_base = *(u64 *)(fp + GBPF_STK_CTX_BASE);
  m.pkt_base = *(u64 *)(fp + GBPF_STK_PKT_BASE);
  m.map_base = *(u64 *)(fp + GBPF_STK_MAP_BASE);
  m.orig_ctx = *(u64 *)(fp + GBPF_ORG_CTX);
  m.prog_type = *(u64 *)(fp + GBPF_STK_PROG_TYPE);
  
  return m;
}
#endif /* _GBPF_HELPERS_H */
