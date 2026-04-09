// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/filter.h>
#include <linux/gbpf.h>

static enum gbpf_arg_kind gbpf_convert_arg_type(enum bpf_arg_type t)
{
	t &= (BPF_BASE_TYPE_LIMIT - 1);

	switch (t) {
	case ARG_CONST_MAP_PTR:
		return GBPF_ARG_CONST_MAP_PTR;
	case ARG_PTR_TO_MAP_KEY:
		return GBPF_ARG_MAP_KEY;
	case ARG_PTR_TO_MAP_VALUE:
		return GBPF_ARG_MAP_VALUE;
	case ARG_PTR_TO_MEM:
		return GBPF_ARG_MEM;
	case ARG_PTR_TO_CTX:
		return GBPF_ARG_CTX;
	case ARG_CONST_SIZE:
	case ARG_CONST_SIZE_OR_ZERO:
		return GBPF_ARG_SIZE;
	default:
		return GBPF_ARG_RAW;
	}
}

static bool gbpf_ret_is_ptr(enum bpf_return_type t)
{
	t &= (BPF_BASE_TYPE_LIMIT - 1);

	switch (t) {
	case RET_PTR_TO_MAP_VALUE:
	case RET_PTR_TO_SOCKET:
	case RET_PTR_TO_TCP_SOCK:
	case RET_PTR_TO_SOCK_COMMON:
	case RET_PTR_TO_MEM:
	case RET_PTR_TO_MEM_OR_BTF_ID:
	case RET_PTR_TO_BTF_ID:
		return true;
	default:
		return false;
	}
}

static int gbpf_find_helper_desc_idx(struct gbpf_helper_desc *desc, u64 func_id)
{
	u32 i;

	for (i = 0; desc[i] != NULL; i++) {
		if (desc[i].func_id == func_id)
			return i;
	}
	return -ENOENT;
}

int gbpf_register_helper_desc(struct bpf_prog *prog,
			      u32 func_id,
			      const struct bpf_func_proto *proto)
{
	struct gbpf_helper_desc *new_descs;
	struct gbpf_helper_desc *d;
	u32 n;

	if (!prog || !prog->aux || !proto || !proto->func)
		return -EINVAL;

	if (gbpf_find_helper_desc_idx(prog, func_id) >= 0)
		return 0;

	n = prog->aux->gbpf_aux.helper_desc_cnt;

	new_descs = krealloc(prog->aux->gbpf_aux.helper_descs,
			     sizeof(*new_descs) * (n + 1),
			     GFP_KERNEL);
	if (!new_descs)
		return -ENOMEM;

	prog->aux->gbpf_aux.helper_descs = new_descs;
	d = &prog->aux->gbpf_aux.helper_descs[n];
	memset(d, 0, sizeof(*d));

	d->func_id = func_id;
	d->func_addr = (u64)(unsigned long)proto->func;
	d->nr_args = 5;
	d->arg_kind[0] = gbpf_convert_arg_type(proto->arg1_type);
	d->arg_kind[1] = gbpf_convert_arg_type(proto->arg2_type);
	d->arg_kind[2] = gbpf_convert_arg_type(proto->arg3_type);
	d->arg_kind[3] = gbpf_convert_arg_type(proto->arg4_type);
	d->arg_kind[4] = gbpf_convert_arg_type(proto->arg5_type);
	d->ret_is_ptr = gbpf_ret_is_ptr(proto->ret_type);

	/* trailing DONTCARE trimming */
	while (d->nr_args > 0 &&
	       d->arg_kind[d->nr_args - 1] == GBPF_ARG_RAW)
		d->nr_args--;

	prog->aux->gbpf_aux.helper_desc_cnt = n + 1;
	return 0;
}
EXPORT_SYMBOL_GPL(gbpf_register_helper_desc);

const struct gbpf_helper_desc *gbpf_find_helper_desc(const struct gbpf_helper_desc *desc,
						     u32 func_id)
{
	int idx;

	if (!prog || !prog->aux)
		return NULL;

	idx = gbpf_find_helper_desc_idx(desc, func_id);
	if (idx < 0)
		return NULL;

	return &prog->aux->gbpf_aux.helper_descs[idx];
}
EXPORT_SYMBOL_GPL(gbpf_find_helper_desc);

void gbpf_free_helper_descs(struct bpf_prog *prog)
{
	if (!prog || !prog->aux)
		return;

	kfree(prog->aux->gbpf_aux.helper_descs);
	prog->aux->gbpf_aux.helper_descs = NULL;
	prog->aux->gbpf_aux.helper_desc_cnt = 0;
}
EXPORT_SYMBOL_GPL(gbpf_free_helper_descs);
