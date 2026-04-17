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

void bpf_tag_sk_filter_ctx(const struct bpf_prog *prog, struct sk_buff *ctx, u8 tag, bool init)
{
	int offset, bit;
	void *tagged_addr;

	for (bit = 0; bit < SOCKET_FILTER_BITMAP_SIZE; bit++) {
		bit = find_next_bit(prog->ctx_read_write_bitmap, SOCKET_FILTER_BITMAP_SIZE, bit);
		offset = bit * BITMAP_COMPRESSION;

		switch (offset)	{
		case offsetof(struct __sk_buff, ifindex):
			tagged_addr = bpf_mte_set_tag(ctx->dev, tag);
			bpf_mte_tag_mem(tagged_addr, sizeof(struct net_device), init);
			ctx->dev = tagged_addr;
			// pr_info("BPF MTE: netdev = %llx", (u64)ctx->dev);
			break;
		case offsetof(struct __sk_buff, family):
		case offsetof(struct __sk_buff, remote_ip4):
		case offsetof(struct __sk_buff, local_ip4):
		case offsetof(struct __sk_buff, remote_port):
		case offsetof(struct __sk_buff, local_port):
		case offsetof(struct __sk_buff, remote_ip6[0]) ...
			 offsetof(struct __sk_buff, remote_ip6[3]):
		case offsetof(struct __sk_buff, local_ip6[0]) ...
			 offsetof(struct __sk_buff, local_ip6[3]):
			if (bpf_mte_get_tag(ctx->sk) != tag) {
				tagged_addr = bpf_mte_set_tag(ctx->sk, tag);
				bpf_mte_tag_mem(tagged_addr, sizeof(struct sock_common), init);
				ctx->sk = tagged_addr;
				// pr_info("BPF MTE: sk = %llx", (u64)ctx->sk);
			}
			break;
		}
	}
}

void bpf_mte_tag_ctx(const struct bpf_prog *prog, const void *ctx,
					size_t size, u8 tag, bool init)
{
	bpf_mte_tag_mem(bpf_mte_set_tag(ctx, tag), size, init);

	switch (prog->type) {
	case BPF_PROG_TYPE_SOCKET_FILTER:
		bpf_tag_sk_filter_ctx(prog, (struct sk_buff *)ctx, tag, init);
		break;
	default:
		break;
	}
}
EXPORT_SYMBOL(bpf_mte_tag_ctx);

#endif /* CONFIG_BPF_SANDBOX_MTE */
