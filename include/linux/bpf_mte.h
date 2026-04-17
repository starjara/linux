/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 University of British Columbia
 * Author: Soo Yee Lim <sooyee@cs.ubc.ca>
 */
#ifndef _BPF_MTE_H
#define _BPF_MTE_H

#include <linux/bpf.h>
#include <linux/math.h>
// #include <linux/bitops.h>

#ifdef CONFIG_BPF_SANDBOX_MTE

#include <asm/memory.h>
#include <asm/cpufeature.h>
#include <asm/mte-kasan.h>

#define BPF_MTE_TAG_KERNEL	0xFF /* native kernel pointers tag */
#define BPF_MTE_TAG_SANDBOX 0xFA
#define BPF_MTE_GRANULE_MASK (MTE_GRANULE_SIZE - 1)

#define bpf_mte_get_tag(addr)	((__u8)((u64)(addr) >> 56))

#ifndef CONFIG_BPF_SANDBOX_MTE_ANALOG_TAG

#define bpf_mte_set_tag(addr, tag)	((void *)__tag_set(addr, tag))
#define bpf_mte_reset_tag(addr)	__untagged_addr(addr)

#else /* CONFIG_BPF_SANDBOX_MTE_ANALOG_TAG */

#define __a_tag_shifted(tag)	((u64)(tag) << 56)
#define __a_untagged_addr(addr)	\
	((__force __typeof__(addr))sign_extend64((__force u64)(addr), 55))

static inline const void *__a_tag_set(const void *addr, u8 tag)
{
	u64 __addr = (u64)addr & ~__a_tag_shifted(0xff);

	return (const void *)(__addr | __a_tag_shifted(tag));
}

#define bpf_mte_set_tag(addr, tag)	((void *)__a_tag_set(addr, tag))
#define bpf_mte_reset_tag(addr)	__a_untagged_addr(addr)

extern int tag_clobber_memory[4];

// NOTE: This is an early implementation that doesn't use dc gva
static inline void __a_mte_set_mem_tag_range(void *addr, size_t size, u8 tag,
					 bool init)
{
	u64 curr, end;

	if (!size)
		return;

	curr = (u64)__a_tag_set(addr, tag);
	end = curr + size;

	/*
	 * 'asm volatile' is required to prevent the compiler to move
	 * the statement outside of the loop.
	 */
	do {
		asm volatile(__MTE_PREAMBLE
					 "ldr x16, =tag_clobber_memory\n\t"
					 "mov x17, %0\n\t"
					 "lsr x17, x17, #49\n\t"
					 "str %0, [x16]\n\t"
					:
					: "r" (curr)
					: "memory");
		curr += MTE_GRANULE_SIZE;
		} while (curr != end);
}

#endif /* CONFIG_BPF_SANDBOX_MTE_ANALOG_TAG */

/**
 * bpf_mte_tag_mem - tag the memory with the MTE tag embedded in addr
 * @addr - range start address, must be aligned to MTE_GRANULE_MASK
 * @size - range size, can be unaligned
 * @init - whether to initialize the memory range (zeroing)
 */
static inline void bpf_mte_tag_mem(const void *addr, size_t size, bool init)
{
	u8 tag;

#ifndef CONFIG_BPF_SANDBOX_MTE_ANALOG_TAG
	if (!system_supports_mte())
		return;
#endif /* CONFIG_BPF_SANDBOX_MTE_ANALOG_TAG */

	tag = bpf_mte_get_tag(addr);

	// pr_info("BPF MTE: tagged_addr = %llx, tag = %d", (u64)addr, tag);

	addr = bpf_mte_reset_tag(addr);

	// pr_info("BPF MTE: untagged addr = %llx", (u64)addr);

#ifdef CONFIG_BPF_SANDBOX_MTE_TAG_CTX
	if ((unsigned long)addr & BPF_MTE_GRANULE_MASK) {
		addr = (const void *)((u64)addr ^ ((u64)addr & BPF_MTE_GRANULE_MASK));
		size += MTE_GRANULE_SIZE;
	}
#endif /* CONFIG_BPF_SANDBOX_MTE_TAG_CTX */
	if (WARN_ON((unsigned long)addr & BPF_MTE_GRANULE_MASK))
		return;
	size = round_up(size, MTE_GRANULE_SIZE);

#ifndef CONFIG_BPF_SANDBOX_MTE_ANALOG_TAG
	mte_set_mem_tag_range((void *)addr, size, tag, init);
#else
	__a_mte_set_mem_tag_range((void *)addr, size, tag, init);
#endif /* CONFIG_BPF_SANDBOX_MTE_ANALOG_TAG */
}

/**
 * bpf_mte_tag_ctx - tag the ctx, including the pointers within
 *
 * @prog - bpf prog structure
 * @ctx - pointer to ctx, assume alignment to MTE_GRANULE_MASK
 * @size - range size, can be unaligned
 * @tag - tag
 * @init - whether to initialize the memory range (zeroing)
 */
void bpf_mte_tag_ctx(const struct bpf_prog *prog, const void *ctx,
					size_t size, u8 tag, bool init);

#else

#define bpf_mte_set_tag(addr, tag)	(addr)
#define bpf_mte_reset_tag(addr)	(addr)

#endif /* CONFIG_BPF_SANDBOX_MTE */

#endif  /* _BPF_MTE_H */
