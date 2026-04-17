/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 University of British Columbia
 * Author: Soo Yee Lim <sooyee@cs.ubc.ca>
 */
#ifndef _BPF_MAP_H
#define _BPF_MAP_H

#include <linux/bpf.h>
#include <linux/bitmap.h>

#ifdef CONFIG_BPF_SFI_MAP_MASKING

#define MAP_BITMAP_SIZE 32

#define IS_MASKING_ENABLED_FOR_MAP(type) ( \
		type == BPF_MAP_TYPE_ARRAY \
		|| type == BPF_MAP_TYPE_HASH \
		)

/**
 * bpf_sandbox_map_info_init() - initialize the structure to keep
 *								 track of registers for map masking.
 *
 * @prog: BPF prog structure
 **/
static inline void bpf_sandbox_map_info_init(struct bpf_prog *prog)
{
	if (!prog->map_info) {
		prog->map_info = kmalloc(sizeof(struct bpf_sandbox_map_jit_info), GFP_KERNEL);
		prog->map_info->map_reg_bitmap = bitmap_zalloc(MAP_BITMAP_SIZE, GFP_KERNEL);
	} else {
		memset(prog->map_info, 0, sizeof(struct bpf_sandbox_map_jit_info));
		bitmap_clear(prog->map_info->map_reg_bitmap, 0, MAP_BITMAP_SIZE);
	}
}

/**
 * is_map_reg() - checks if a register contains a map value by
 *					  checking the bitmap stored in BPF prog.
 *
 * @prog: BPF prog structure
 * @reg: register to be checked if it contains a map value
 **/
static inline bool is_map_reg(const struct bpf_prog *prog, u8 reg)
{
	int bit;

	for (bit = 0; bit < MAP_BITMAP_SIZE; bit++) {
		bit = find_next_bit(prog->map_info->map_reg_bitmap, MAP_BITMAP_SIZE, bit);
		if (bit == reg) {
			// pr_info("BPF MAP: bit = %d, reg = %d", bit, reg);
			return true;
		}
	}

	return false;
}

void bpf_sandbox_add_map(struct bpf_map *map);
void bpf_sandbox_delete_map(struct bpf_map *map);
void bpf_sandbox_add_map_lookup(const struct bpf_map_ops *ops);
// NOTE: we don't support deletion of lookup func because even
// when a map is freed, there could be other maps of the same type
bool is_active_map(u64 map);
bool is_map_lookup(u64 fn);

#endif /* CONFIG_BPF_SFI_MAP_MASKING */
#endif
