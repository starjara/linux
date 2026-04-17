// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 University of British Columbia
 *
 * Author: Soo Yee Lim <sooyee@cs.ubc.ca>
 */

#include <linux/bpf_mte.h>
#include <linux/bpf_ctx.h>

#ifdef CONFIG_BPF_SANDBOX_MTE

#ifdef CONFIG_BPF_SANDBOX_MTE_ANALOG_TAG
int tag_clobber_memory[4];
#endif /* CONFIG_BPF_SANDBOX_MTE_ANALOG_TAG */

void bpf_tag_bpf_sock_skc(const struct bpf_prog *prog, struct sk_buff *ctx,
								u8 tag, bool init)
{
	void *tagged_addr;
	struct sock_common *skc = &ctx->sk->__sk_common;

	if (skc && virt_addr_valid(skc)) {
		tagged_addr = bpf_mte_set_tag(&skc->skc_family, tag);
		bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);

		tagged_addr = bpf_mte_set_tag(&skc->skc_rcv_saddr, tag);
		bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);

		tagged_addr = bpf_mte_set_tag(&skc->skc_daddr, tag);
		bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);

		tagged_addr = bpf_mte_set_tag(&skc->skc_num, tag);
		bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);

		tagged_addr = bpf_mte_set_tag(&skc->skc_dport, tag);
		bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);

		tagged_addr = bpf_mte_set_tag((void *)&skc->skc_state, tag);
		bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);

		tagged_addr = bpf_mte_set_tag(skc->skc_v6_daddr.s6_addr32, tag);
		bpf_mte_tag_mem(tagged_addr, 4*sizeof(__u32), init);

		tagged_addr = bpf_mte_set_tag(skc->skc_v6_rcv_saddr.s6_addr32, tag);
		bpf_mte_tag_mem(tagged_addr, 4*sizeof(__u32), init);
	}
}

void bpf_tag__sk_buff_bpf_sock(const struct bpf_prog *prog, struct sk_buff *ctx,
								u8 tag, bool init)
{
	void *tagged_addr;

	if (ctx->sk && virt_addr_valid(ctx->sk)) {
		tagged_addr = bpf_mte_set_tag(&ctx->sk->sk_bound_dev_if, tag);
		bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);

		tagged_addr = bpf_mte_set_tag(&ctx->sk->sk_type, tag);
		bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);

		tagged_addr = bpf_mte_set_tag(&ctx->sk->sk_protocol, tag);
		bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);

		tagged_addr = bpf_mte_set_tag(&ctx->sk->sk_mark, tag);
		bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);

		tagged_addr = bpf_mte_set_tag(&ctx->sk->sk_priority, tag);
		bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);

		tagged_addr = bpf_mte_set_tag(&ctx->sk->sk_rx_queue_mapping, tag);
		bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);

		tagged_addr = bpf_mte_set_tag(&ctx->sk->sk_type, tag);
		bpf_mte_tag_mem(&ctx->sk->sk_type, MTE_GRANULE_SIZE, init);

		bpf_tag_bpf_sock_skc(prog, ctx, tag, init);
		ctx->sk = bpf_mte_set_tag(ctx->sk, tag);
	}
}

void bpf_tag_sk_filter_ctx(const struct bpf_prog *prog, struct sk_buff *ctx, u8 tag, bool init)
{
	int offset, bit;
	void *tagged_addr;
	struct sock_common *skc;
	struct qdisc_skb_cb *qdisc_cb;
	struct skb_shared_info *skb_shared;
	struct bpf_skb_data_end_mirror *bpf_skb_data;

	skc = &ctx->sk->__sk_common;
	qdisc_cb = qdisc_skb_cb(ctx);
	skb_shared = skb_shinfo(ctx);
	bpf_skb_data = (struct bpf_skb_data_end_mirror *)ctx->cb;

	for (bit = 0; bit < SOCKET_FILTER_BITMAP_SIZE; bit++) {
		bit = find_next_bit(prog->ctx_read_write_bitmap, SOCKET_FILTER_BITMAP_SIZE, bit);
		offset = bit * BITMAP_COMPRESSION;

		switch (offset)	{
		case offsetof(struct __sk_buff, len):
			tagged_addr = bpf_mte_set_tag(&ctx->len, tag);
			bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);
			break;
		case offsetof(struct __sk_buff, protocol):
			tagged_addr = bpf_mte_set_tag(&ctx->protocol, tag);
			bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);
			break;
		case offsetof(struct __sk_buff, vlan_proto):
			tagged_addr = bpf_mte_set_tag(&ctx->vlan_proto, tag);
			bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);
			break;
		case offsetof(struct __sk_buff, priority):
			tagged_addr = bpf_mte_set_tag(&ctx->priority, tag);
			bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);
			break;
		case offsetof(struct __sk_buff, ingress_ifindex):
			tagged_addr = bpf_mte_set_tag(&ctx->skb_iif, tag);
			bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);
			break;
		case offsetof(struct __sk_buff, hash):
			tagged_addr = bpf_mte_set_tag(&ctx->hash, tag);
			bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);
			break;
		case offsetof(struct __sk_buff, mark):
			tagged_addr = bpf_mte_set_tag(&ctx->mark, tag);
			bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);
			break;
		case offsetof(struct __sk_buff, pkt_type):
			tagged_addr = bpf_mte_set_tag(&ctx->__pkt_type_offset[0], tag);
			bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);
			break;
		case offsetof(struct __sk_buff, queue_mapping):
			tagged_addr = bpf_mte_set_tag(&ctx->queue_mapping, tag);
			bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);
			break;
		case offsetof(struct __sk_buff, vlan_present):
			tagged_addr = bpf_mte_set_tag(&ctx->vlan_all, tag);
			bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);
			break;
		case offsetof(struct __sk_buff, vlan_tci):
			tagged_addr = bpf_mte_set_tag(&ctx->vlan_tci, tag);
			bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);
			break;
		// This is a void *, tag according to what it is casted to
		case offsetof(struct __sk_buff, data):
			tagged_addr = bpf_mte_set_tag(&ctx->data, tag);
			bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);
			break;
		case offsetof(struct __sk_buff, tc_index):
			tagged_addr = bpf_mte_set_tag(&ctx->tc_index, tag);
			bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);
			break;
		case offsetof(struct __sk_buff, napi_id):
			tagged_addr = bpf_mte_set_tag(&ctx->napi_id, tag);
			bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);
			break;
		/* net_device */
		case offsetof(struct __sk_buff, ifindex):
			tagged_addr = bpf_mte_set_tag(&ctx->dev->ifindex, tag);
			bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);
			tagged_addr = bpf_mte_set_tag(&ctx->dev, tag);
			bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);
			ctx->dev = bpf_mte_set_tag(ctx->dev, tag);
			// pr_info("BPF MTE: netdev = %llx", (u64)ctx->dev);
			break;
		/* qdisc_skb_cb */
		case offsetof(struct __sk_buff, cb[0]) ...
			 offsetofend(struct __sk_buff, cb[4]) - 1:
			tagged_addr = bpf_mte_set_tag(qdisc_cb->data, tag);
			bpf_mte_tag_mem(tagged_addr, 5*sizeof(__u32), init);
			tagged_addr = bpf_mte_set_tag(&qdisc_cb, tag);
			bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);
			break;
		case offsetof(struct __sk_buff, tc_classid):
			tagged_addr = bpf_mte_set_tag(&qdisc_cb->tc_classid, tag);
			bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);
			tagged_addr = bpf_mte_set_tag(&qdisc_cb, tag);
			bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);
			break;
		case offsetof(struct __sk_buff, wire_len):
			tagged_addr = bpf_mte_set_tag(&qdisc_cb->pkt_len, tag);
			bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);
			tagged_addr = bpf_mte_set_tag(&qdisc_cb, tag);
			bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);
			break;
		/* bpf_skb_data_end */
		case offsetof(struct __sk_buff, data_meta):
			// TODO
			break;
		case offsetof(struct __sk_buff, data_end):
			// TODO
			break;
		/* sock_common */
		case offsetof(struct __sk_buff, family):
			tagged_addr = bpf_mte_set_tag(&skc->skc_family, tag);
			bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);
			ctx->sk = bpf_mte_set_tag(ctx->sk, tag);
			break;
		case offsetof(struct __sk_buff, remote_ip4):
			tagged_addr = bpf_mte_set_tag(&skc->skc_daddr, tag);
			bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);
			ctx->sk = bpf_mte_set_tag(ctx->sk, tag);
			break;
		case offsetof(struct __sk_buff, local_ip4):
			tagged_addr = bpf_mte_set_tag(&skc->skc_rcv_saddr, tag);
			bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);
			ctx->sk = bpf_mte_set_tag(ctx->sk, tag);
			break;
		case offsetof(struct __sk_buff, remote_ip6[0]) ...
			 offsetof(struct __sk_buff, remote_ip6[3]):
			tagged_addr = bpf_mte_set_tag(skc->skc_v6_daddr.s6_addr32, tag);
			bpf_mte_tag_mem(tagged_addr, 4*sizeof(__u32), init);
			ctx->sk = bpf_mte_set_tag(ctx->sk, tag);
			break;
		case offsetof(struct __sk_buff, local_ip6[0]) ...
			 offsetof(struct __sk_buff, local_ip6[3]):
			tagged_addr = bpf_mte_set_tag(skc->skc_v6_rcv_saddr.s6_addr32, tag);
			bpf_mte_tag_mem(tagged_addr, 4*sizeof(__u32), init);
			ctx->sk = bpf_mte_set_tag(ctx->sk, tag);
			break;
		case offsetof(struct __sk_buff, remote_port):
			tagged_addr = bpf_mte_set_tag(&skc->skc_dport, tag);
			bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);
			ctx->sk = bpf_mte_set_tag(ctx->sk, tag);
			break;
		case offsetof(struct __sk_buff, local_port):
			tagged_addr = bpf_mte_set_tag(&skc->skc_num, tag);
			bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);
			ctx->sk = bpf_mte_set_tag(ctx->sk, tag);
			break;
		/* skb_shared_info */
		case offsetof(struct __sk_buff, gso_segs):
			tagged_addr = bpf_mte_set_tag(&skb_shared->gso_segs, tag);
			bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);
			break;
		case offsetof(struct __sk_buff, gso_size):
			tagged_addr = bpf_mte_set_tag(&skb_shared->gso_size, tag);
			bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);
			break;
		case offsetof(struct __sk_buff, hwtstamp):
			tagged_addr = bpf_mte_set_tag(&skb_shared->hwtstamps.hwtstamp, tag);
			bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);
			break;
		case offsetof(struct __sk_buff, tstamp):
			tagged_addr = bpf_mte_set_tag(ctx->__pkt_vlan_present_offset, tag);
			bpf_mte_tag_mem(ctx->__pkt_vlan_present_offset, MTE_GRANULE_SIZE, init);
			tagged_addr = bpf_mte_set_tag(&ctx->tstamp, tag);
			bpf_mte_tag_mem(tagged_addr, MTE_GRANULE_SIZE, init);
			break;
		case offsetof(struct __sk_buff, tstamp_type):
			tagged_addr = bpf_mte_set_tag(ctx->__pkt_vlan_present_offset, tag);
			bpf_mte_tag_mem(ctx->__pkt_vlan_present_offset, MTE_GRANULE_SIZE, init);
			break;
		case offsetof(struct __sk_buff, sk):
			bpf_tag__sk_buff_bpf_sock(prog, ctx, tag, init);
			break;
		}
	}
}

void bpf_tag_xdp_ctx(const struct bpf_prog *prog, struct xdp_buff *ctx, u8 tag, bool init)
{
	int offset, bit;
	struct xdp_rxq_info *rxq = ctx->rxq;
	struct xdp_txq_info *txq = ctx->txq;
	int data_size_bit = (u64)ctx->data_end - (u64)ctx->data;
	int metadata_size_bit = (u64)ctx->data - (u64)ctx->data_meta;

	for (bit = 0; bit < XDP_BITMAP_SIZE; bit++) {
		bit = find_next_bit(prog->ctx_read_write_bitmap, XDP_BITMAP_SIZE, bit);
		offset = bit * BITMAP_COMPRESSION;
		// pr_info("CTX XDP: bit = %d, offset = %d", bit, offset);

		switch (offset)	{
		case offsetof(struct xdp_md, data):
			bpf_mte_tag_mem(bpf_mte_set_tag(&ctx->data, tag),
						MTE_GRANULE_SIZE, init);
			bpf_mte_tag_mem(bpf_mte_set_tag(ctx->data, tag),
						data_size_bit, init);
			break;
		case offsetof(struct xdp_md, data_meta):
			bpf_mte_tag_mem(bpf_mte_set_tag(&ctx->data_meta, tag),
						MTE_GRANULE_SIZE, init);
			if (metadata_size_bit > 0)
				bpf_mte_tag_mem(bpf_mte_set_tag(ctx->data_meta, tag),
						metadata_size_bit, init);
			break;
		case offsetof(struct xdp_md, data_end):
			bpf_mte_tag_mem(bpf_mte_set_tag(&ctx->data_end, tag),
						MTE_GRANULE_SIZE, init);
			break;
		case offsetof(struct xdp_md, ingress_ifindex):
			bpf_mte_tag_mem(bpf_mte_set_tag(&ctx->rxq, tag),
						MTE_GRANULE_SIZE, init);
			bpf_mte_tag_mem(bpf_mte_set_tag(rxq->dev, tag),
						MTE_GRANULE_SIZE, init);
			bpf_mte_tag_mem(bpf_mte_set_tag(&rxq->dev->ifindex, tag),
						MTE_GRANULE_SIZE, init);
			break;
		case offsetof(struct xdp_md, rx_queue_index):
			bpf_mte_tag_mem(bpf_mte_set_tag(&ctx->rxq, tag),
						MTE_GRANULE_SIZE, init);
			bpf_mte_tag_mem(bpf_mte_set_tag(&rxq->queue_index, tag),
						MTE_GRANULE_SIZE, init);
			break;
		case offsetof(struct xdp_md, egress_ifindex):
			bpf_mte_tag_mem(bpf_mte_set_tag(&ctx->txq, tag),
						MTE_GRANULE_SIZE, init);
			bpf_mte_tag_mem(bpf_mte_set_tag(txq->dev, tag),
						MTE_GRANULE_SIZE, init);
			bpf_mte_tag_mem(bpf_mte_set_tag(&txq->dev->ifindex, tag),
						MTE_GRANULE_SIZE, init);
			break;
		}
	}
}

void bpf_mte_tag_ctx(const struct bpf_prog *prog, const void *ctx,
					size_t size, u8 tag, bool init)
{
	switch (prog->type) {
	case BPF_PROG_TYPE_SOCKET_FILTER:
		bpf_tag_sk_filter_ctx(prog, (struct sk_buff *)ctx, tag, init);
		break;
	case BPF_PROG_TYPE_XDP:
		bpf_tag_xdp_ctx(prog, (struct xdp_buff *)ctx, tag, init);
		break;
	case BPF_PROG_TYPE_KPROBE:
		bpf_mte_tag_mem(bpf_mte_set_tag(ctx, tag),
						sizeof(bpf_user_pt_regs_t), init);
		break;
	default:
		break;
	}
}
EXPORT_SYMBOL(bpf_mte_tag_ctx);

#endif /* CONFIG_BPF_SANDBOX_MTE */
