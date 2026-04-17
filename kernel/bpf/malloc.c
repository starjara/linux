// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2023 University of British Columbia
 * Author: Soo Yee Lim <sooyee@cs.ubc.ca>
 */
#include <linux/filter.h>
#include <linux/bpf_mte.h>
#include <linux/bpf_malloc.h>
#include <linux/bpf_sandbox.h>

typedef u64 header_t;
#define BPF_ALIGNMENT 8
#define BPF_HEADER_SIZE sizeof(header_t)
#define BPF_ALIGN(size) (((size) + (BPF_ALIGNMENT - 1)) & ~(BPF_ALIGNMENT - 1))

static void bpf_sandbox_add_sync_pair(u64 copy, u64 to_sync)
{
	for (int i = 0; i < MAX_SYNC_PAIRS; i++) {
		if (current_sandbox_info->sync_pairs[i].sandbox_ptr == 0) {
			current_sandbox_info->sync_pairs[i].sandbox_ptr = copy;
			current_sandbox_info->sync_pairs[i].kernel_ptr = to_sync;
			return;
		}
	}
	pr_info("BPF Sandbox: Insufficient space to store sync pairs.");
}

static void bpf_sandbox_remove_sync_pair(u64 copy)
{
	for (int i = 0; i < MAX_SYNC_PAIRS; i++) {
		if (current_sandbox_info->sync_pairs[i].sandbox_ptr == copy) {
			current_sandbox_info->sync_pairs[i].sandbox_ptr = 0;
			current_sandbox_info->sync_pairs[i].kernel_ptr = 0;
			return;
		}
	}
	pr_info("BPF Sandbox: %llx not synced, unable to remove from sync pairs.", copy);
}

// Allocate and return the previous program break, which also points to the new
// area if increment is successful
static void *bpf_sbrk(size_t size)
{
	void *ret;

	if (unlikely(current_sandbox_info->free_size < size)) {
		pr_info("BPF Sandbox: free space on heap = %llu", current_sandbox_info->free_size);
		pr_info("BPF Sandbox: memory requested = %lu", size);
		panic("BPF Sandbox: fail to allocate memory dynamically.");
		return NULL;         // return NULL won't be reached
	}
	current_sandbox_info->prog_brk += size;
	current_sandbox_info->free_size -= size;
	ret = (void *)current_sandbox_info->prog_brk - size;
	return bpf_mte_set_tag(ret, BPF_MTE_TAG_SANDBOX);
}

void *bpf_sandbox_get_kernel_ptr(u64 sandbox_ptr)
{
	for (int i = 0; i < MAX_SYNC_PAIRS; i++)
		if (current_sandbox_info->sync_pairs[i].sandbox_ptr == sandbox_ptr)
			return (void *)current_sandbox_info->sync_pairs[i].kernel_ptr;
	pr_info("BPF Sandbox: Fail to find a match for sandbox ptr %llx.", sandbox_ptr);
	return NULL;
}

void *bpf_malloc(size_t size, void *to_sync)
{
	u64 untagged_kptr = bpf_mte_set_tag((u64)to_sync, BPF_MTE_TAG_KERNEL);
	size_t blk_size = BPF_ALIGN(size + BPF_HEADER_SIZE);
	header_t *header = bpf_sbrk(blk_size);

	*header = blk_size | 1; // set allocated bit
	if (likely(to_sync))
		bpf_sandbox_add_sync_pair((u64)header + BPF_HEADER_SIZE, untagged_kptr);
	return (void *)header + BPF_HEADER_SIZE;
}
EXPORT_SYMBOL(bpf_malloc);

void bpf_free(void *sandbox_ptr)
{
	header_t *header;

	bpf_sandbox_remove_sync_pair((u64)sandbox_ptr);
	header = (void *)sandbox_ptr - BPF_HEADER_SIZE;
	// unset allocated bit, though right now we're not using for reallocation
	*header = *header & ~1L;
}
