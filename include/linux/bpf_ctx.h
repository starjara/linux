/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 University of British Columbia
 * Author: Soo Yee Lim <sooyee@cs.ubc.ca>
 */
#ifndef _BPF_CTX_H
#define _BPF_CTX_H

#include <linux/bpf.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/perf_event.h>
#include <linux/bpf_malloc.h>

#include <net/xdp.h>
#include <net/sock.h>
#include <net/busy_poll.h>
#include <net/sch_generic.h>

// Compressing the bitmap representation by sizeof(__u32) aka 4 bytes won't
// work because some fields are __u8 1 byte
#define BITMAP_COMPRESSION 4 // compressable because all fields are __u32
#define XDP_BITMAP_SIZE 6
#define PERF_EVENT_BITMAP_SIZE 32
#define SOCKET_FILTER_BITMAP_SIZE 64

#ifdef CONFIG_BPF_SANDBOX_CTX

#define IS_SANDBOX_CTX_SUPPORTED(type) ( \
		type == BPF_PROG_TYPE_SOCKET_FILTER \
		|| type == BPF_PROG_TYPE_PERF_EVENT \
		|| type == BPF_PROG_TYPE_XDP \
		|| type == BPF_PROG_TYPE_KPROBE \
		)

/**
 * Maintenance Note: New fields can be added to the BPF contexts (i.e., more
 *				   fields in the kernel data structure can be exposed to
 *				   BPF programs), but only at the end of the structure.
 *				   When porting to a newer kernel version, simply check if
 *				   any new fields are added to the end of the BPF context.
 **/

/**
 * Maintenance Note: A mirror of the structs defined in <linux/filter.h>
 *				   is defined here to avoid the circular dependency hell.
 *				   When porting to a different kernel version, update these.
 **/
struct bpf_skb_data_end_mirror {
	struct qdisc_skb_cb qdisc_cb;
	void *data_meta;
	void *data_end;
};

/**
 * bpf_create_sk_filter_ctx() - copy corresponding fields in __sk_buff from sk_buff.
 *
 * @prog: BPF prog structure
 * @kernel_ctx: the actual kernel object (struct sk_buff)
 * @bpf_ctx: the BPF mirror of sk_buff (struct __sk_buff)
 **/
void bpf_create_sk_filter_ctx(const struct bpf_prog *prog,
	const struct sk_buff *kernel_ctx, struct __sk_buff *bpf_ctx);

void bpf_create__sk_buff_tstamp_read(const struct bpf_prog *prog,
	const struct sk_buff *kernel_ctx, struct __sk_buff *bpf_ctx);

void bpf_create__sk_buff_tstamp_type(const struct bpf_prog *prog,
	const struct sk_buff *kernel_ctx, struct __sk_buff *bpf_ctx);

void bpf_create_bpf_sock_skc(const struct bpf_prog *prog,
	const struct sk_buff *kernel_ctx, struct bpf_sock *bpf_sk);

void bpf_create__sk_buff_bpf_sock(const struct bpf_prog *prog,
	const struct sk_buff *kernel_ctx, struct __sk_buff *bpf_ctx);
/**
 * bpf_create_perf_event_ctx() - copy fields
 *								 in bpf_perf_event_data_kern
 *								 to bpf_perf_event_data.
 *
 * @prog: BPF prog structure
 * @kernel_ctx: the actual kernel obj (struct bpf_perf_event_data_kern)
 * @bpf_ctx: the BPF mirror of kernel obj (struct bpf_perf_event_data)
 **/
void bpf_create_perf_event_ctx(const struct bpf_prog *prog,
	const struct bpf_perf_event_data_kern *kernel_ctx,
	struct bpf_perf_event_data *bpf_ctx);

/**
 * bpf_create_xdp_ctx() - copy fields
 *						in xdp_buff
 *						to xdp_md.
 *
 * @prog: BPF prog structure
 * @kernel_ctx: the actual kernel obj (struct xdp_buff)
 * @bpf_ctx: the BPF mirror of kernel obj (struct xdp_md)
 **/
void bpf_create_xdp_ctx(const struct bpf_prog *prog,
	const struct xdp_buff *kernel_ctx,
	struct xdp_md *bpf_ctx);

/**
 * bpf_sync_sk_filter_ctx() - copy writeable fields in __sk_buff to sk_buff.
 *
 * @prog: BPF prog structure
 * @kernel_ctx: the actual kernel object (struct sk_buff)
 * @bpf_ctx: the BPF mirror of sk_buff (struct __sk_buff)
 **/
void bpf_sync_sk_filter_ctx(const struct bpf_prog *prog,
	const struct sk_buff *kernel_ctx, struct __sk_buff *bpf_ctx);

/**
 * bpf_sync_xdp_ctx() - copy writeable fields in xdp_md to xdp_buff.
 *
 * @prog: BPF prog structure
 * @kernel_ctx: the actual kernel object (struct xdp_buff)
 * @bpf_ctx: the BPF mirror of sk_buff (struct xdp_md)
 **/
void bpf_sync_xdp_ctx(const struct bpf_prog *prog,
	const struct xdp_buff *kernel_ctx, struct xdp_md *bpf_ctx);

/**
 * bpf_create_prog_ctx() - eBPF programs can only access limited fields
 *						 in the kernel data structure (e.g., __sk_buff
 *						 is a user accessible mirror of the in-kernel
 *						   sk_buff). This function creates the context
 *						 that eBPF programs actually interacts with
 *						   (e.g., __sk_buff) at runtime.
 *
 * @prog_type: program type ID
 * @kernel_ctx: kernel data structure
 * @bpf_ctx: BPF mirror of the kernel data structure
 **/
void bpf_create_prog_ctx(const struct bpf_prog *prog,
	const void *kernel_ctx, void *bpf_ctx);

/**
 * bpf_sync_kernel_ctx() - eBPF programs have write access to limited
 *						   fields in the kernel data structure. This
 *						   function must be called upon the return
 *						   of eBPF program to sync any writes back
 *						   to the actual kernel data structure.
 *
 * @prog_type: program type ID
 * @kernel_ctx: kernel data structure
 * @bpf_ctx: BPF mirror of the kernel data structure
 **/
void bpf_sync_kernel_ctx(const struct bpf_prog *prog,
	const void *kernel_ctx, void *bpf_ctx);

#endif  /* CONFIG_BPF_SANDBOX_CTX */

/**
 * record_ctx_accesses() - record which fields are accessed by the program.
 *						   This function is called when at during
 *						   post-verification rewrite (i.e, is_valid_accesses
 *						   is already called so all the fields recorded here
 *						   are valid accesses.)
 *
 * @verifier_env: BPF verifier environment
 **/
void record_ctx_accesses(void *verifier_env);

static inline void __bpf_ctx_bitmap_alloc(struct bpf_prog *prog, int nbits)
{
	prog->ctx_read_write_bitmap = bitmap_zalloc(nbits, GFP_KERNEL);
	prog->ctx_write_bitmap = bitmap_zalloc(nbits, GFP_KERNEL);
}

static inline void bpf_ctx_bitmap_alloc(struct bpf_prog *prog, int type)
{
	switch (type) {
	case BPF_PROG_TYPE_XDP:
		__bpf_ctx_bitmap_alloc(prog, XDP_BITMAP_SIZE);
		break;
	case BPF_PROG_TYPE_SOCKET_FILTER:
		__bpf_ctx_bitmap_alloc(prog, SOCKET_FILTER_BITMAP_SIZE);
		break;
	case BPF_PROG_TYPE_PERF_EVENT:
		__bpf_ctx_bitmap_alloc(prog, PERF_EVENT_BITMAP_SIZE);
		break;
	default:
		// pr_info("BPF Sandbox: bitmap not supported for prog type %d", type);
		break;
	}
}

#endif  /* _BPF_CTX_H */
