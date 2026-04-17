// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 University of British Columbia
 * Author: Soo Yee Lim <sooyee@cs.ubc.ca>
 */

#include <linux/bpf_verifier.h>
#include <linux/bpf_ctx.h>
#include <linux/bitmap.h>

void record_ctx_accesses(void *verifier_env)
{
	const struct bpf_verifier_env *env = verifier_env;
	const int insn_cnt = env->prog->len;
	struct bpf_insn *insn = env->prog->insnsi;
	enum bpf_access_type type;
	bool ctx_access;
	int i, bit;

	for (i = 0; i < insn_cnt; i++, insn++) {
		if ((int)env->insn_aux_data[i].ptr_type != PTR_TO_CTX)
			continue;

		if (insn->code == (BPF_LDX | BPF_MEM | BPF_B) ||
		    insn->code == (BPF_LDX | BPF_MEM | BPF_H) ||
		    insn->code == (BPF_LDX | BPF_MEM | BPF_W) ||
		    insn->code == (BPF_LDX | BPF_MEM | BPF_DW)) {
			type = BPF_READ;
			ctx_access = true;
		} else if (insn->code == (BPF_STX | BPF_MEM | BPF_B) ||
			   insn->code == (BPF_STX | BPF_MEM | BPF_H) ||
			   insn->code == (BPF_STX | BPF_MEM | BPF_W) ||
			   insn->code == (BPF_STX | BPF_MEM | BPF_DW) ||
			   insn->code == (BPF_ST | BPF_MEM | BPF_B) ||
			   insn->code == (BPF_ST | BPF_MEM | BPF_H) ||
			   insn->code == (BPF_ST | BPF_MEM | BPF_W) ||
			   insn->code == (BPF_ST | BPF_MEM | BPF_DW)) {
			type = BPF_WRITE;
			ctx_access = BPF_CLASS(insn->code) == BPF_STX;
		} else {
			continue;
		}

		if (!ctx_access)
			continue;

		bit = insn->off / BITMAP_COMPRESSION;

		if (!env->prog->ctx_read_write_bitmap || !env->prog->ctx_write_bitmap)
			return;

		switch (type) {
		case BPF_READ:
			bitmap_set(env->prog->ctx_read_write_bitmap, bit, 1);
			// pr_info("read field at offset %d", bit);
			break;
		case BPF_WRITE:
			bitmap_set(env->prog->ctx_read_write_bitmap, bit, 1);
			bitmap_set(env->prog->ctx_write_bitmap, bit, 1);
			// pr_info("write field at offset %d", bit);
			break;
		}
	}

}

#ifdef CONFIG_BPF_SANDBOX_CTX
#ifdef CONFIG_BPF_SANDBOX_CTX_BITMAP
/**
 * Maintenance Note: move the __u8 tstamp_type to the last field
 **/
void bpf_create_sk_filter_ctx(const struct bpf_prog *prog,
	const struct sk_buff *kernel_ctx, struct __sk_buff *bpf_ctx)
{
	int offset, bit;
	struct bpf_skb_data_end_mirror *bpf_skb_data;
	struct sock_common *skc = &kernel_ctx->sk->__sk_common;
	struct qdisc_skb_cb *qdisc_cb = qdisc_skb_cb(kernel_ctx);

	// if (bitmap_empty(prog->ctx_read_write_bitmap, SOCKET_FILTER_BITMAP_SIZE))
	//	return;

	for (bit = 0; bit < SOCKET_FILTER_BITMAP_SIZE; bit++) {
		bit = find_next_bit(prog->ctx_read_write_bitmap, SOCKET_FILTER_BITMAP_SIZE, bit);
		offset = bit * BITMAP_COMPRESSION;
		// pr_info("CTX SK_FILTER: bit = %d", bit);

		// if (bit == SOCKET_FILTER_BITMAP_SIZE)
		//	break;

		switch (offset)	{
		case offsetof(struct __sk_buff, len):
			bpf_ctx->len = kernel_ctx->len;
			break;
		case offsetof(struct __sk_buff, protocol):
			bpf_ctx->protocol = kernel_ctx->protocol;
			break;
		case offsetof(struct __sk_buff, vlan_proto):
			bpf_ctx->vlan_proto = kernel_ctx->vlan_proto;
			break;
		case offsetof(struct __sk_buff, priority):
			bpf_ctx->priority = kernel_ctx->priority;
			break;
		case offsetof(struct __sk_buff, ingress_ifindex):
			bpf_ctx->ingress_ifindex = kernel_ctx->skb_iif;
			break;
		case offsetof(struct __sk_buff, ifindex):
			bpf_ctx->ifindex = kernel_ctx->dev->ifindex;
			break;
		case offsetof(struct __sk_buff, hash):
			bpf_ctx->hash = kernel_ctx->hash;
			break;
		case offsetof(struct __sk_buff, mark):
			bpf_ctx->mark = kernel_ctx->mark;
			break;
		case offsetof(struct __sk_buff, pkt_type):
			bpf_ctx->pkt_type = kernel_ctx->__pkt_type_offset[0] & PKT_TYPE_MAX;
			#ifdef __BIG_ENDIAN_BITFIELD
			bpf_ctx->pkt_type = bpf_ctx->pkt_type >> 5;
			#endif /* __BIG_ENDIAN_BITFIELD */
			break;
		case offsetof(struct __sk_buff, queue_mapping):
			bpf_ctx->queue_mapping = kernel_ctx->queue_mapping;
			break;
		case offsetof(struct __sk_buff, vlan_present):
			bpf_ctx->vlan_present = kernel_ctx->vlan_all != 0 ?
									1 : kernel_ctx->vlan_all;
			break;
		case offsetof(struct __sk_buff, vlan_tci):
			bpf_ctx->vlan_tci = kernel_ctx->vlan_tci;
			break;
		case offsetof(struct __sk_buff, data):
			memcpy(&bpf_ctx->data, kernel_ctx->data, sizeof(__u32));
			break;
		case offsetof(struct __sk_buff, tc_index):
			#ifdef CONFIG_NET_SCHED
			bpf_ctx->tc_index = kernel_ctx->tc_index; //pass
			#else
			bpf_ctx->tc_index = 0;
			#endif /* CONFIG_NET_SCHED */
			break;
		case offsetof(struct __sk_buff, napi_id):
			#ifdef CONFIG_NET_RX_BUSY_POLL
			bpf_ctx->napi_id = kernel_ctx->napi_id; //pass? (zero matches)
			if (bpf_ctx->napi_id < MIN_NAPI_ID)
				bpf_ctx->napi_id = 0;
			#else
			bpf_ctx->napi_id = 0;
			#endif /* CONFIG_NET_RX_BUSY_POLL */
			break;
		/* qdisc_skb_cb */
		case offsetof(struct __sk_buff, cb[0]) ...
			 offsetofend(struct __sk_buff, cb[4]) - 1:
			memcpy(bpf_ctx->cb, qdisc_cb->data, 5*sizeof(__u32));
			break;
		case offsetof(struct __sk_buff, tc_classid):
			bpf_ctx->tc_classid = qdisc_cb->tc_classid;
			break;
		case offsetof(struct __sk_buff, wire_len):
			bpf_ctx->wire_len = qdisc_cb->pkt_len;
			break;
		/* bpf_skb_data_end */
		case offsetof(struct __sk_buff, data_meta):
			bpf_skb_data = (struct bpf_skb_data_end_mirror *)kernel_ctx->cb;
			bpf_ctx->data_meta = (__u32)(u64) bpf_skb_data->data_meta;
			break;
		case offsetof(struct __sk_buff, data_end):
			bpf_skb_data = (struct bpf_skb_data_end_mirror *)kernel_ctx->cb;
			bpf_ctx->data_end = (__u32)(u64) bpf_skb_data->data_end;
			break;
		/* sock_common */
		case offsetof(struct __sk_buff, family):
			bpf_ctx->family = skc->skc_family;
			break;
		case offsetof(struct __sk_buff, remote_ip4):
			bpf_ctx->remote_ip4 = skc->skc_daddr;
			break;
		case offsetof(struct __sk_buff, local_ip4):
			bpf_ctx->local_ip4 = skc->skc_rcv_saddr;
			break;
		case offsetof(struct __sk_buff, remote_ip6[0]) ...
			 offsetof(struct __sk_buff, remote_ip6[3]):
			#if IS_ENABLED(CONFIG_IPV6)
			memcpy(bpf_ctx->remote_ip6, skc->skc_v6_daddr.s6_addr32, 4*sizeof(__u32));
			#else
			memset(bpf_ctx->remote_ip6, 0, 4*sizeof(__u32));
			#endif /* CONFIG_IPV6 */
			break;
		case offsetof(struct __sk_buff, local_ip6[0]) ...
			 offsetof(struct __sk_buff, local_ip6[3]):
			#if IS_ENABLED(CONFIG_IPV6)
			memcpy(bpf_ctx->local_ip6, skc->skc_v6_rcv_saddr.s6_addr32,
					4*sizeof(__u32));
			#else
			memset(bpf_ctx->local_ip6, 0, 4*sizeof(__u32));
			#endif /* CONFIG_IPV6 */
			break;
		case offsetof(struct __sk_buff, remote_port):
			bpf_ctx->remote_port = skc->skc_dport;
			#ifndef __BIG_ENDIAN_BITFIELD
			bpf_ctx->remote_port = bpf_ctx->remote_port << 16;
			#endif /* __BIG_ENDIAN_BITFIELD */
			break;
		case offsetof(struct __sk_buff, local_port):
			bpf_ctx->local_port = skc->skc_num;
			break;
		/* skb_shared_info */
		case offsetof(struct __sk_buff, gso_segs):
			#ifdef NET_SKBUFF_DATA_USES_OFFSET
			bpf_ctx->gso_segs = skb_shinfo(kernel_ctx)->gso_segs;
			#else
			*shinfo = kernel_ctx->end;
			bpf_ctx->gso_segs = shinfo->gso_segs;
			#endif /* NET_SKBUFF_DATA_USES_OFFSET */
			break;
		case offsetof(struct __sk_buff, gso_size):
			#ifdef NET_SKBUFF_DATA_USES_OFFSET
			bpf_ctx->gso_size = skb_shinfo(kernel_ctx)->gso_size;
			#else
			*shinfo = kernel_ctx->end;
			bpf_ctx->gso_size = shinfo->gso_size;
			#endif /* NET_SKBUFF_DATA_USES_OFFSET */
			break;
		case offsetof(struct __sk_buff, hwtstamp):
			#ifdef NET_SKBUFF_DATA_USES_OFFSET
			bpf_ctx->hwtstamp = skb_shinfo(kernel_ctx)->hwtstamps.hwtstamp;
			#else
			*shinfo = kernel_ctx->end;
			bpf_ctx->hwtstamp = shinfo->hwtstamps.hwtstamp;
			#endif /* NET_SKBUFF_DATA_USES_OFFSET */
			break;
		case offsetof(struct __sk_buff, tstamp):
			bpf_create__sk_buff_tstamp_read(prog, kernel_ctx, bpf_ctx);
			break;
		case offsetof(struct __sk_buff, tstamp_type):
			bpf_create__sk_buff_tstamp_type(prog, kernel_ctx, bpf_ctx);
			break;
		case offsetof(struct __sk_buff, sk):
			bpf_create__sk_buff_bpf_sock(prog, kernel_ctx, bpf_ctx);
			break;
		}
	}
}

void bpf_create_perf_event_ctx(const struct bpf_prog *prog,
	const struct bpf_perf_event_data_kern *kernel_ctx,
	struct bpf_perf_event_data *bpf_ctx)
{
	int offset, bit;

	if (bitmap_empty(prog->ctx_read_write_bitmap, PERF_EVENT_BITMAP_SIZE))
		return;

	for (bit = 0; bit < PERF_EVENT_BITMAP_SIZE; bit++) {
		bit = find_next_bit(prog->ctx_read_write_bitmap, PERF_EVENT_BITMAP_SIZE, bit);
		offset = bit * BITMAP_COMPRESSION;
		// pr_info("CTX PERF_EVENT: bit = %d", bit);

		// if (bit == PERF_EVENT_BITMAP_SIZE)
		//	break;

		switch (offset)	{
		case offsetof(struct bpf_perf_event_data, sample_period):
			bpf_ctx->sample_period = kernel_ctx->data->period;
			break;
		case offsetof(struct bpf_perf_event_data, addr):
			bpf_ctx->addr = kernel_ctx->data->addr;
			break;
		case offsetof(struct bpf_perf_event_data, regs):
			memcpy(&bpf_ctx->regs, kernel_ctx->regs,
					sizeof(bpf_user_pt_regs_t));
			break;
		}
	}
}

void bpf_create_xdp_ctx(const struct bpf_prog *prog,
	const struct xdp_buff *kernel_ctx,
	struct xdp_md *bpf_ctx)
{
	int offset, bit;
	void *xdp_data, *xdp_metadata;
	struct xdp_rxq_info *rxq = kernel_ctx->rxq;
	struct xdp_txq_info *txq = kernel_ctx->txq;
	int data_size_bit = (u64)kernel_ctx->data_end - (u64)kernel_ctx->data;
	int metadata_size_bit = (u64)kernel_ctx->data - (u64)kernel_ctx->data_meta;

	// if (bitmap_empty(prog->ctx_read_write_bitmap, XDP_BITMAP_SIZE))
	//	return;

	for (bit = 0; bit < XDP_BITMAP_SIZE; bit++) {
		bit = find_next_bit(prog->ctx_read_write_bitmap, XDP_BITMAP_SIZE, bit);
		offset = bit * BITMAP_COMPRESSION;
		// pr_info("CTX XDP: bit = %d, offset = %d", bit, offset);

		// if (bit == XDP_BITMAP_SIZE)
		//	break;

		switch (offset)	{
		case offsetof(struct xdp_md, data):
			xdp_data = bpf_malloc(data_size_bit, NULL);
			memcpy(xdp_data, kernel_ctx->data, data_size_bit);
			bpf_ctx->data = (u64)xdp_data;
			break;
		case offsetof(struct xdp_md, data_meta):
			if (metadata_size_bit > 0) {
				xdp_metadata = bpf_malloc(metadata_size_bit, NULL);
				memcpy(xdp_metadata, kernel_ctx->data_meta, metadata_size_bit);
				bpf_ctx->data_meta = (u64)xdp_metadata;
			} else
				bpf_ctx->data_meta = bpf_ctx->data;
			break;
		case offsetof(struct xdp_md, data_end):
			bpf_ctx->data_end = bpf_ctx->data + data_size_bit;
			break;
		case offsetof(struct xdp_md, ingress_ifindex):
			bpf_ctx->ingress_ifindex = rxq->dev->ifindex;
			break;
		case offsetof(struct xdp_md, rx_queue_index):
			bpf_ctx->rx_queue_index = rxq->queue_index;
			break;
		case offsetof(struct xdp_md, egress_ifindex):
			bpf_ctx->egress_ifindex = txq->dev->ifindex;
			break;
		}
	}
}

void bpf_sync_sk_filter_ctx(const struct bpf_prog *prog,
	const struct sk_buff *kernel_ctx, struct __sk_buff *bpf_ctx)
{
	int offset, bit;
	struct qdisc_skb_cb *qdisc_cb;

	// if (bitmap_empty(prog->ctx_write_bitmap, SOCKET_FILTER_BITMAP_SIZE))
	//	return;

	for (bit = 0; bit < SOCKET_FILTER_BITMAP_SIZE; bit++) {
		bit = find_next_bit(prog->ctx_write_bitmap, SOCKET_FILTER_BITMAP_SIZE, bit);
		offset = bit * BITMAP_COMPRESSION;

		switch (offset)	{
		case offsetof(struct __sk_buff, cb[0]) ...
			 offsetofend(struct __sk_buff, cb[4]) - 1:
			qdisc_cb = qdisc_skb_cb(kernel_ctx);
			memcpy(qdisc_cb->data, bpf_ctx->cb, 5*sizeof(__u32));
			break;
		}
	}
}

void bpf_sync_xdp_ctx(const struct bpf_prog *prog,
	const struct xdp_buff *kernel_ctx, struct xdp_md *bpf_ctx)
{
	int offset, bit;

	// if (bitmap_empty(prog->ctx_write_bitmap, XDP_BITMAP_SIZE))
	//	return;

	for (bit = 0; bit < XDP_BITMAP_SIZE; bit++) {
		bit = find_next_bit(prog->ctx_write_bitmap, XDP_BITMAP_SIZE, bit);
		offset = bit * BITMAP_COMPRESSION;

		switch (offset)	{
		case offsetof(struct xdp_md, rx_queue_index):
			kernel_ctx->rxq->queue_index = bpf_ctx->rx_queue_index;
			break;
		}
	}
}

#endif /* CONFIG_BPF_SANDBOX_CTX_BITMAP */
#endif  /* CONFIG_BPF_SANDBOX_CTX */
