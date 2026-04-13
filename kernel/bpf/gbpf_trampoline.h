#ifndef _GBPF_HELPERS_H
#define _GBPF_HELPERS_H

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/kernel.h>
#include <linux/filter.h>
#include <linux/gbpf.h>

typedef u64 (*gbpf_helper_fn_t)(u64, u64, u64, u64, u64);

/*
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
  m.map_desc_base = *(u64 *)(fp + GBPF_STK_MAP_BASE);
  m.orig_ctx = *(u64 *)(fp + GBPF_ORG_CTX);
  m.prog_type = *(u64 *)(fp + GBPF_STK_PROG_TYPE);
  
  return m;
}
*/

static __always_inline u64 *gbpf_read_gaux(struct gbpf_aux **gaux)
{
  u64 fp;
  u64 imm;

  asm volatile (
		"mv %0, s9\n\t"
		"mv %1, s11\n\t"
		: "=r"(fp), "=r"(imm)
		:
		:);

  *gaux = fp;

  return imm;
}
#endif /* _GBPF_HELPERS_H */
