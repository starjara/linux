// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 University of British Columbia
 * Author: Soo Yee Lim <sooyee@cs.ubc.ca>
 */

#include <linux/bpf_ctx.h>

#ifdef CONFIG_BPF_SANDBOX_CTX

void bpf_create__sk_buff_tstamp_read(const struct bpf_prog *prog,
	const struct sk_buff *kernel_ctx, struct __sk_buff *bpf_ctx)
{
	#ifdef CONFIG_NET_CLS_ACT
		if (!prog->tstamp_type_access) {
		  //memcpy(&bpf_ctx->tstamp_type, kernel_ctx->__pkt_vlan_present_offset, sizeof(__u64));
		  memcpy(&bpf_ctx->tstamp, &kernel_ctx->tstamp,
					sizeof(__u64));
			bpf_ctx->tstamp = bpf_ctx->tstamp &
							(TC_AT_INGRESS_MASK |
							SKB_MONO_DELIVERY_TIME_MASK);
			if (bpf_ctx->tstamp
				== (TC_AT_INGRESS_MASK | SKB_MONO_DELIVERY_TIME_MASK)) {
				bpf_ctx->tstamp = 0;
				return;
			}
		}
	#endif /* CONFIG_NET_CLS_ACT */
	bpf_ctx->tstamp = kernel_ctx->tstamp;
}


void bpf_create__sk_buff_tstamp_type(const struct bpf_prog *prog,
	const struct sk_buff *kernel_ctx, struct __sk_buff *bpf_ctx)
{
  //memcpy(&bpf_ctx->tstamp_type, kernel_ctx->__pkt_vlan_present_offset, sizeof(__u8));
  //memcpy(&bpf_ctx->tstamp_type, kernel_ctx->__pkt_vlan_present_offset, sizeof(__u8));
	if (bpf_ctx->tstamp_type > SKB_MONO_DELIVERY_TIME_MASK) {
		bpf_ctx->tstamp_type = BPF_SKB_TSTAMP_UNSPEC;
		return;
	}
	bpf_ctx->tstamp_type = BPF_SKB_TSTAMP_DELIVERY_MONO;
}

void bpf_create_bpf_sock_skc(const struct bpf_prog *prog,
	const struct sk_buff *kernel_ctx, struct bpf_sock *bpf_sk)
{
	struct sock_common *skc = &kernel_ctx->sk->__sk_common;

	if (skc && virt_addr_valid(skc)) {
		bpf_sk->family = skc->skc_family; //check
		bpf_sk->src_ip4 = skc->skc_rcv_saddr; //check
		bpf_sk->dst_ip4 = skc->skc_daddr; //check
		bpf_sk->src_port = skc->skc_num;
		bpf_sk->dst_port = skc->skc_dport;
		bpf_sk->state = skc->skc_state;
		#if IS_ENABLED(CONFIG_IPV6)
			memcpy(bpf_sk->dst_ip6, skc->skc_v6_daddr.s6_addr32, 4*sizeof(__u32));
			memcpy(bpf_sk->src_ip6, skc->skc_v6_rcv_saddr.s6_addr32,
					4*sizeof(__u32));
		#else
			memset(bpf_sk->dst_ip6, 0, 4*sizeof(__u32));
			memset(bpf_sk->src_ip6, 0, 4*sizeof(__u32));
		#endif /* CONFIG_IPV6 */
	}
}

void bpf_create__sk_buff_bpf_sock(const struct bpf_prog *prog,
	const struct sk_buff *kernel_ctx, struct __sk_buff *bpf_ctx)
{
	struct sock *kernel_sk = kernel_ctx->sk;

	if (kernel_sk && virt_addr_valid(kernel_sk)) {
		bpf_ctx->sk = bpf_malloc(sizeof(struct bpf_sock), NULL);

		bpf_ctx->sk->bound_dev_if = kernel_sk->sk_bound_dev_if;
		bpf_ctx->sk->type = kernel_sk->sk_type;
		bpf_ctx->sk->protocol = kernel_sk->sk_protocol;
		bpf_ctx->sk->mark = kernel_sk->sk_mark;
		bpf_ctx->sk->priority = kernel_sk->sk_priority;
		bpf_ctx->sk->rx_queue_mapping = kernel_sk->sk_rx_queue_mapping;
		bpf_create_bpf_sock_skc(prog, kernel_ctx, bpf_ctx->sk);
	} else
		bpf_ctx->sk = NULL; // for NULL testing on the user's end
}

#ifdef CONFIG_BPF_SANDBOX_CTX_GENERIC

static void bpf_create__sk_buff_shinfo(const struct bpf_prog *prog,
	const struct sk_buff *kernel_ctx, struct __sk_buff *bpf_ctx)
{
	struct skb_shared_info *shinfo;

	#ifdef NET_SKBUFF_DATA_USES_OFFSET
		shinfo = skb_shinfo(kernel_ctx);
	#else
		*shinfo = kernel_ctx->end; //check
	#endif /* NET_SKBUFF_DATA_USES_OFFSET */

	if (shinfo && virt_addr_valid(shinfo)) {
		bpf_ctx->gso_segs = shinfo->gso_segs;
		bpf_ctx->gso_size = shinfo->gso_size;
		//not accessible by socket filter (NOT TESTED)
		bpf_ctx->hwtstamp = shinfo->hwtstamps.hwtstamp;
	}
}

static void bpf_create__sk_buff_skc(const struct bpf_prog *prog,
	const struct sk_buff *kernel_ctx, struct __sk_buff *bpf_ctx)
{
	struct sock_common *skc = &kernel_ctx->sk->__sk_common;

	if (skc && virt_addr_valid(skc)) {
		bpf_ctx->family = skc->skc_family; //check
		bpf_ctx->remote_port = skc->skc_dport;
		#ifndef __BIG_ENDIAN_BITFIELD
		bpf_ctx->remote_port = bpf_ctx->remote_port << 16;
		#endif /* __BIG_ENDIAN_BITFIELD */
		bpf_ctx->local_port = skc->skc_num;
		bpf_ctx->remote_ip4 = skc->skc_daddr; //check
		bpf_ctx->local_ip4 = skc->skc_rcv_saddr; //check
		#if IS_ENABLED(CONFIG_IPV6)
			memcpy(bpf_ctx->remote_ip6, skc->skc_v6_daddr.s6_addr32, 4*sizeof(__u32));
			memcpy(bpf_ctx->local_ip6, skc->skc_v6_rcv_saddr.s6_addr32,
					4*sizeof(__u32));
		#else
			memset(bpf_ctx->remote_ip6, 0, 4*sizeof(__u32));
			memset(bpf_ctx->local_ip6, 0, 4*sizeof(__u32));
		#endif /* CONFIG_IPV6 */
	}
}

static void bpf_create__sk_buff_qdisc_cb(const struct bpf_prog *prog,
	const struct sk_buff *kernel_ctx, struct __sk_buff *bpf_ctx)
{
	struct qdisc_skb_cb *qdisc_cb = qdisc_skb_cb(kernel_ctx);

	if (qdisc_cb && virt_addr_valid(qdisc_cb)) {
		memcpy(bpf_ctx->cb, qdisc_cb->data, 5*sizeof(__u32)); //pass
		//not accessible by socket filter (NOT TESTED)
		bpf_ctx->tc_classid = qdisc_cb->tc_classid;
		bpf_ctx->wire_len = qdisc_cb->pkt_len; //check
	}
}

static void bpf_create__sk_buff_netdev(const struct bpf_prog *prog,
	const struct sk_buff *kernel_ctx, struct __sk_buff *bpf_ctx)
{
	struct net_device *netdev = kernel_ctx->dev;

	if (netdev && virt_addr_valid(netdev))
		bpf_ctx->ifindex = netdev->ifindex;
}

static void bpf_create__sk_buff_bpf_skb_data_end(const struct bpf_prog *prog,
	const struct sk_buff *kernel_ctx, struct __sk_buff *bpf_ctx)
{
	struct bpf_skb_data_end_mirror *bpf_skb_data;

	bpf_skb_data = (struct bpf_skb_data_end_mirror *)kernel_ctx->cb;

	if (bpf_skb_data && virt_addr_valid(bpf_skb_data)) {
		bpf_ctx->data_meta = (__u32)(u64) bpf_skb_data->data_meta;
		bpf_ctx->data_end = (__u32)(u64) bpf_skb_data->data_end;
	}
}

void bpf_create_sk_filter_ctx(const struct bpf_prog *prog,
	const struct sk_buff *kernel_ctx, struct __sk_buff *bpf_ctx)
{
	//TODO: keep a simplified copy of convert_ctx_access,
	//	  with cb->access=1 and all those BUILD_BUG_ON
	//TODO: as we move target_size in convert_ctx_access needs to be kept

	bpf_ctx->len = kernel_ctx->len; //pass
	bpf_ctx->protocol = kernel_ctx->protocol; //pass
	bpf_ctx->vlan_proto = kernel_ctx->vlan_proto; //pass
	bpf_ctx->priority = kernel_ctx->priority; //pass
	bpf_ctx->ingress_ifindex = kernel_ctx->skb_iif; //pass
	bpf_ctx->hash = kernel_ctx->hash; //pass
	bpf_ctx->mark = kernel_ctx->mark; //pass
	bpf_ctx->queue_mapping = kernel_ctx->queue_mapping; //pass
	bpf_ctx->vlan_tci = kernel_ctx->vlan_tci; //pass
	bpf_ctx->vlan_present = kernel_ctx->vlan_all != 0 ? 1 : kernel_ctx->vlan_all; //pass

	bpf_ctx->pkt_type = kernel_ctx->__pkt_type_offset[0] & PKT_TYPE_MAX; //pass
	#ifdef __BIG_ENDIAN_BITFIELD
		bpf_ctx->pkt_type = bpf_ctx->pkt_type >> 5;
	#endif /* __BIG_ENDIAN_BITFIELD */

	//not accessible by socket filter (NOT TESTED)
	if (kernel_ctx->data && virt_addr_valid(kernel_ctx->data))
	   memcpy(&bpf_ctx->data, kernel_ctx->data, sizeof(__u32));

	#ifdef CONFIG_NET_SCHED
		bpf_ctx->tc_index = kernel_ctx->tc_index; //pass
	#else
		bpf_ctx->tc_index = 0;
	#endif /* CONFIG_NET_SCHED */

	#ifdef CONFIG_NET_RX_BUSY_POLL
		bpf_ctx->napi_id = kernel_ctx->napi_id; //pass? (zero matches)
		if (bpf_ctx->napi_id < MIN_NAPI_ID)
			bpf_ctx->napi_id = 0;
	#else
		bpf_ctx->napi_id = 0;
	#endif /* CONFIG_NET_RX_BUSY_POLL */

	//not accessible by socket filter (NOT TESTED)
	bpf_create__sk_buff_tstamp_read(prog, kernel_ctx, bpf_ctx);
	//not accessible by socket filter (NOT TESTED)
	bpf_create__sk_buff_tstamp_type(prog, kernel_ctx, bpf_ctx);

	//not accessible by socket filter (NOT TESTED)
	bpf_create__sk_buff_skc(prog, kernel_ctx, bpf_ctx);
	bpf_create__sk_buff_shinfo(prog, kernel_ctx, bpf_ctx);
	//pass (to test again with convert_ctx_accesses removed)
	bpf_create__sk_buff_netdev(prog, kernel_ctx, bpf_ctx);
	//not accessible by socket filter (NOT TESTED)
	bpf_create__sk_buff_qdisc_cb(prog, kernel_ctx, bpf_ctx);
	//not accessible by socket filter (NOT TESTED)
	bpf_create__sk_buff_bpf_skb_data_end(prog, kernel_ctx, bpf_ctx);

	// TODO: malloc tested, but the field values not verified
	bpf_create__sk_buff_bpf_sock(prog, kernel_ctx, bpf_ctx);

	/********************************************/
	// pr_info("----------------------------------");
	// pr_info("len = %d, protocol = %d, vlan_proto = %d",
	//		bpf_ctx->len, bpf_ctx->protocol, bpf_ctx->vlan_proto);
	// pr_info("priority = %d, ingress_ifindex = %d, hash = %d",
	//		bpf_ctx->priority, bpf_ctx->ingress_ifindex, bpf_ctx->hash);
	// pr_info("mark = %d, queue_mapping = %d, vlan_tci = %d",
	//		bpf_ctx->mark, bpf_ctx->queue_mapping, bpf_ctx->vlan_tci);
	// pr_info("pkt_type = %d, vlan_present = %d, tc_index = %d",
	//		bpf_ctx->pkt_type, bpf_ctx->vlan_present, bpf_ctx->tc_index);
	// pr_info("ifindex = %d, napi_id = %d, tstamp = %lld, tstamp_type = %d",
	//		bpf_ctx->ifindex, bpf_ctx->napi_id, bpf_ctx->tstamp, bpf_ctx->tstamp_type);
	// pr_info("gso_segs = %d, gso_size = %d", bpf_ctx->gso_segs, bpf_ctx->gso_size);
	// pr_info("actual sk_buff = %llx, __sk_buff = %llx, sock = %llx, bpf_ctx = %llx",
	//		(u64)kernel_ctx, (u64)bpf_ctx, (u64)bpf_ctx->sk, (u64)bpf_ctx);
	// pr_info("sk->bound = %llx, sk->family = %llx",
	//		(u64)&bpf_ctx->sk->bound_dev_if, (u64)&bpf_ctx->sk->family);
	/********************************************/
}

void bpf_create_perf_event_ctx(const struct bpf_prog *prog,
	const struct bpf_perf_event_data_kern *kernel_ctx,
	struct bpf_perf_event_data *bpf_ctx)
{
	bpf_ctx->sample_period = kernel_ctx->data->period;
	bpf_ctx->addr = kernel_ctx->data->addr;
	memcpy(&bpf_ctx->regs, kernel_ctx->regs,
					sizeof(bpf_user_pt_regs_t));

	/********************************************/
	// pr_info("----------------------------------");
	// pr_info("period = %lld, addr = %llx",
	//		bpf_ctx->sample_period, bpf_ctx->addr);
	/********************************************/
}

void bpf_create_xdp_ctx(const struct bpf_prog *prog,
	const struct xdp_buff *kernel_ctx,
	struct xdp_md *bpf_ctx)
{
	void *xdp_data, *xdp_metadata;
	struct xdp_rxq_info *rxq = kernel_ctx->rxq;
	struct xdp_txq_info *txq = kernel_ctx->txq;
	int data_size_bit = (u64)kernel_ctx->data_end - (u64)kernel_ctx->data;
	int metadata_size_bit = (u64)kernel_ctx->data - (u64)kernel_ctx->data_meta;

	// No need to null check, bpf_malloc panics if there's not enough space
	if (metadata_size_bit > 0) {
		xdp_metadata = bpf_malloc(metadata_size_bit, NULL);
		memcpy(xdp_metadata, kernel_ctx->data_meta, metadata_size_bit);
	}

	xdp_data = bpf_malloc(data_size_bit, NULL);
	memcpy(xdp_data, kernel_ctx->data, data_size_bit);

	bpf_ctx->data = (u64)xdp_data;
	bpf_ctx->data_end = bpf_ctx->data + data_size_bit;
	bpf_ctx->data_meta = metadata_size_bit > 0 ? (u64)xdp_metadata :
						 bpf_ctx->data;

	// pr_info("BPF Sandbox: xdp_kdata = %llx, xdp_kend = %llx, xdp_kmeta = %llx",
	//		(u64)kernel_ctx->data, (u64)kernel_ctx->data_end,
	//		(u64)kernel_ctx->data_meta);
	// pr_info("BPF Sandbox: xdp_data = %lx, xdp_end = %lx, xdp_meta = %lx",
	//		bpf_ctx->data, bpf_ctx->data_end, bpf_ctx->data_meta);
	// struct ethhdr *khdr = (struct ethhdr *)kernel_ctx->data;
	// struct ethhdr *hdr = (struct ethhdr *)bpf_ctx->data;
	// pr_info("BPF Sandbox: xdp_k_proto = %d, xdp_proto = %d",
	//		khdr->h_proto, hdr->h_proto);
	// pr_info("BPF Sandbox: size of data in sandbox = %d, size of ethhdr = %d",
	//		data_size_bit, sizeof(struct ethhdr));

	if (rxq && virt_addr_valid(rxq)) {
		bpf_ctx->ingress_ifindex = (rxq->dev && virt_addr_valid(rxq->dev)) ?
									rxq->dev->ifindex : 0;
		bpf_ctx->rx_queue_index = rxq->queue_index;
	}

	if (txq && virt_addr_valid(txq))
		bpf_ctx->egress_ifindex = (txq->dev && virt_addr_valid(txq->dev)) ?
									txq->dev->ifindex : 0;
}

void bpf_sync_sk_filter_ctx(const struct bpf_prog *prog,
	const struct sk_buff *kernel_ctx, struct __sk_buff *bpf_ctx)
{
	struct qdisc_skb_cb *qdisc_cb = qdisc_skb_cb(kernel_ctx);

	if (qdisc_cb && virt_addr_valid(qdisc_cb))
		memcpy(qdisc_cb->data, bpf_ctx->cb, 5*sizeof(__u32));
}

void bpf_sync_xdp_ctx(const struct bpf_prog *prog,
	const struct xdp_buff *kernel_ctx, struct xdp_md *bpf_ctx)
{
	struct xdp_rxq_info *rxq = kernel_ctx->rxq;

	if (bpf_prog_is_offloaded(prog->aux) && rxq && virt_addr_valid(rxq))
		rxq->queue_index = bpf_ctx->rx_queue_index;

}

#endif /* CONFIG_BPF_SANDBOX_CTX_GENERIC */

// No need for bitmap implementation
void bpf_create_kprobe_ctx(const struct bpf_prog *prog,
	const void *kernel_ctx, void *bpf_ctx)
{
	// NOTE: not tested on x86_64
	memcpy(bpf_ctx, kernel_ctx, sizeof(bpf_user_pt_regs_t));
}

void bpf_create_prog_ctx(const struct bpf_prog *prog,
	const void *kernel_ctx, void *bpf_ctx)
{
	switch (prog->type) {
	case BPF_PROG_TYPE_SOCKET_FILTER:
		bpf_create_sk_filter_ctx(prog, kernel_ctx, bpf_ctx);
		break;
	case BPF_PROG_TYPE_PERF_EVENT:
		bpf_create_perf_event_ctx(prog, kernel_ctx, bpf_ctx);
		break;
	case BPF_PROG_TYPE_XDP:
		bpf_create_xdp_ctx(prog, kernel_ctx, bpf_ctx); // pass
		break;
	case BPF_PROG_TYPE_KPROBE:
		bpf_create_kprobe_ctx(prog, kernel_ctx, bpf_ctx);
		break;
	default:
		// pr_info_once("BPF Sandbox: ctx support not yet added for prog type %d",
				// prog->type);
		break;
	}
}
EXPORT_SYMBOL(bpf_create_prog_ctx);

void bpf_sync_kernel_ctx(const struct bpf_prog *prog,
	const void *kernel_ctx, void *bpf_ctx)
{
	switch (prog->type) {
	case BPF_PROG_TYPE_SOCKET_FILTER:
		bpf_sync_sk_filter_ctx(prog, kernel_ctx, bpf_ctx);
		break;
	case BPF_PROG_TYPE_XDP:
		bpf_sync_xdp_ctx(prog, kernel_ctx, bpf_ctx); // pass
		break;
	case BPF_PROG_TYPE_PERF_EVENT:
		break;	// no writes allowed, no syncing required upon exit
	case BPF_PROG_TYPE_KPROBE:
		break; // no writes allowed, no syncing required upon exit
	default:
		// pr_info("BPF Sandbox: ctx support not yet added for prog type %d",
				// prog->type);
		break;
	}
}
EXPORT_SYMBOL(bpf_sync_kernel_ctx);

#endif  /* CONFIG_BPF_SANDBOX_CTX */
