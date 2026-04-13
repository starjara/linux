#ifndef _GBPF_HELPERS_H
#define _GBPF_HELPERS_H

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/kernel.h>
#include <linux/filter.h>
#include <linux/gbpf.h>

typedef u64 (*gbpf_helper_fn_t)(u64, u64, u64, u64, u64);

static __always_inline u64 *gbpf_read_gaux(struct gbpf_aux **gaux)
{
  u64 fp;
  u64 imm;

  asm volatile (
		"mv %0, s10\n\t"
		"mv %1, s11\n\t"
		: "=r"(fp), "=r"(imm)
		:
		:);

  *gaux = *(u64 *)(fp + GBPF_STK_SAVE_GAUX);

  return imm;
}
#endif /* _GBPF_HELPERS_H */
