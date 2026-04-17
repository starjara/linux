/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 University of British Columbia
 * Author: Soo Yee Lim <sooyee@cs.ubc.ca>
 */
#ifndef _BPF_MALLOC_H
#define _BPF_MALLOC_H

#include <linux/types.h>

void *bpf_sandbox_get_kernel_ptr(u64 sandbox_ptr);
void *bpf_malloc(size_t size, void *to_sync);
void bpf_free(void *sandbox_ptr);
#endif
