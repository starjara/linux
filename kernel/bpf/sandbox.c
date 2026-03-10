/* Garden : Copying SafeBPF code */
#include <linux/cpu.h>
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/bpf_sandbox.h>
#include <linux/skmsg.h>
#include <linux/perf_event.h>
#include <linux/netfilter.h>
#include <net/netfilter/nf_bpf_link.h>
#include <linux/bpf_lsm.h>
#include <linux/btf_ids.h>
#include "disasm.h"
#include <linux/threads.h>
#include <linux/filter.h>
#include <linux/bpf_verifier.h>

union bpf_sandbox *sandboxes;
void *sandbox_ctx;
uintptr_t bpf_sandbox_and_mask;
EXPORT_SYMBOL(bpf_sandbox_and_mask);
uintptr_t bpf_sandbox_or_masks[CONFIG_NR_CPUS];
EXPORT_SYMBOL(bpf_sandbox_or_masks);



struct bpf_sandbox_env {
	DECLARE_HASHTABLE(func_ht, 7);
	DECLARE_HASHTABLE(skb_func_ht, 4);
	DECLARE_HASHTABLE(xdp_func_ht, 2);
};

struct bpf_helper {
	u64 			addr;
	struct hlist_node	hnode;
};

static DEFINE_PER_CPU(int, bpf_sandbox_nesting);


extern const struct bpf_verifier_ops * const bpf_verifier_ops[];
static struct bpf_sandbox_env *bpf_sandbox_env;
/*
static __always_inline int msb(int b)
{
	int p = 0;

	b = b / 2;
	while (b != 0){
		b = b / 2;
		p++;
	}
	return p;
}

static __always_inline uintptr_t gen_or_mask(volatile void *p, size_t s)
{
//	uintptr_t m = (((uintptr_t)1 << (msb(s) + 1)) -1) - s;

	return (uintptr_t)p;
}

static __always_inline uintptr_t gen_and_mask(size_t s)
{
	uintptr_t m = (((uintptr_t)1 << (msb(s) + 1)) - 1) -s;

	return (uintptr_t)m;
}
*/


size_t bpf_ctx_size_map[] = {
	#define BPF_PROG_TYPE(_id, _name, prog_ctx_type, kern_ctx_type) \
		[_id] = sizeof(kern_ctx_type),
	#define BPF_MAP_TYPE(_id, _ops)
	#define BPF_LINK_TYPE(_id, _name)
	#include <linux/bpf_types.h>
	#undef BPF_PROG_TYPE
	#undef BPF_MAP_TYPE
	#undef BPF_LINK_TYPE
	0,
};
EXPORT_SYMBOL(bpf_ctx_size_map);
EXPORT_SYMBOL(sandboxes);
EXPORT_SYMBOL(sandbox_ctx);







static void func_ht_add(u64 prog_id, u64 fn)
{
	struct bpf_helper *a;

	if (fn == 0)
		return;

	a = kzalloc(sizeof(struct bpf_helper), GFP_ATOMIC);
	if (!a)
		return;

	a->addr = fn;
	hash_add(bpf_sandbox_env[prog_id].func_ht, &a->hnode, fn);
}

static void skb_func_ht_add(int i, u64 prog_id, u64 fn)
{
	struct bpf_helper *a;

	switch (i) {
	case BPF_FUNC_skb_store_bytes:
	case BPF_FUNC_skb_load_bytes:
	case BPF_FUNC_l3_csum_replace:
	case BPF_FUNC_l4_csum_replace:
	case BPF_FUNC_clone_redirect:
	case BPF_FUNC_get_cgroup_classid:
	case BPF_FUNC_skb_vlan_push:
	case BPF_FUNC_skb_vlan_pop:
	case BPF_FUNC_skb_get_tunnel_key:
	case BPF_FUNC_skb_set_tunnel_key:
	case BPF_FUNC_get_route_realm:
	case BPF_FUNC_skb_get_tunnel_opt:
	case BPF_FUNC_skb_set_tunnel_opt:
	case BPF_FUNC_skb_change_proto:
	case BPF_FUNC_skb_change_type:
	case BPF_FUNC_skb_under_cgroup:
	case BPF_FUNC_get_hash_recalc:
	case BPF_FUNC_skb_change_head:
	case BPF_FUNC_skb_change_tail:
	case BPF_FUNC_skb_pull_data:
	case BPF_FUNC_csum_update:
	case BPF_FUNC_set_hash_invalid:
	case BPF_FUNC_get_socket_cookie:
	case BPF_FUNC_get_socket_uid:
	case BPF_FUNC_set_hash:
	case BPF_FUNC_skb_adjust_room:
	case BPF_FUNC_sk_redirect_map:
	case BPF_FUNC_skb_get_xfrm_state:
	case BPF_FUNC_skb_load_bytes_relative:
	case BPF_FUNC_sk_redirect_hash:
	case BPF_FUNC_lwt_push_encap:
	case BPF_FUNC_lwt_seg6_store_bytes:
	case BPF_FUNC_lwt_seg6_adjust_srh:
	case BPF_FUNC_lwt_seg6_action:
	case BPF_FUNC_skb_cgroup_id:
	case BPF_FUNC_skb_ancestor_cgroup_id:
	case BPF_FUNC_skb_ecn_set_ce:
	case BPF_FUNC_sk_assign:
	case BPF_FUNC_csum_level:
	case BPF_FUNC_skb_cgroup_classid:
	case BPF_FUNC_skb_set_tstamp:
		a = kzalloc(sizeof(struct bpf_helper), GFP_ATOMIC);
		if (!a)
			return;
		a->addr = fn;
		hash_add(bpf_sandbox_env[prog_id].skb_func_ht, &a->hnode, fn);
		break;
	}
}

static void xdp_func_ht_add(int i, u64 prog_id, u64 fn)
{
	struct bpf_helper *a;

	switch (i) {
	case BPF_FUNC_xdp_adjust_head:
	case BPF_FUNC_xdp_adjust_meta:
	case BPF_FUNC_xdp_adjust_tail:
	case BPF_FUNC_xdp_get_buff_len:
	case BPF_FUNC_xdp_load_bytes:
	case BPF_FUNC_xdp_store_bytes:
		a = kzalloc(sizeof(struct bpf_helper), GFP_ATOMIC);
		if (!a)
			return;
		a->addr = fn;
		hash_add(bpf_sandbox_env[prog_id].xdp_func_ht, &a->hnode, fn);
		break;
	}
}




static int __init bpf_sandbox_init(void)
{
	sandboxes = kmalloc(sizeof(union bpf_sandbox) * nr_cpu_ids, GFP_KERNEL);

	if (!sandboxes) {
		pr_err("Failed to allocate BPF sandboxes!\n");
		return -ENOMEM;
	}
	
	bpf_sandbox_and_mask = gen_and_mask(BPF_SANDBOX_SIZE);
	for (int i = 0; i < nr_cpu_ids; i++) {
		bpf_sandbox_or_masks[i] = gen_or_mask(sandboxes[i].mem.private, BPF_SANDBOX_SIZE);
	//	pr_info("[sandbox.c] CPU[%d] or_mask: 0x%lx (at address: %px)\n", i, bpf_sandbox_or_masks[i], &bpf_sandbox_or_masks[i]);
}
	

	pr_info("[sandbox.c] BPF Sandbox initialized successfully. sandboxes: %px, and_mask: 0x%lx\n", 
         sandboxes, bpf_sandbox_and_mask);


	return 0;
}

core_initcall(bpf_sandbox_init);




static __always_inline bool is_allowed_helper(u64 prog_id, u64 fn)
{
	struct bpf_helper *a;

	struct bpf_sandbox_env *env = &bpf_sandbox_env[prog_id];

	hash_for_each_possible(bpf_sandbox_env[prog_id].func_ht, a, hnode, (u64)fn) {
		if (a->addr == fn){
	//		pr_info("Yes. you can access.\n");
			return true;
		}
	}
	//pr_info("Access Denied.\n");
	return false;
}


__always_inline bool is_skb_helper(u64 prog_id, u64 fn)
{
	struct bpf_helper *a;

	struct bpf_sandbox_env *env = &bpf_sandbox_env[prog_id];

	hash_for_each_possible(env->skb_func_ht, a, hnode, (u64)fn) {
		if (a->addr == fn){
	//		pr_info("Yes. You are.\n");
			return true;
		}
	}
	//pr_info("No. you are not.\n");
	return false;
}
EXPORT_SYMBOL(is_skb_helper);

static __always_inline bool is_xdp_helper(u64 prog_id, u64 fn)
{
	struct bpf_helper *a;

	struct bpf_sandbox_env *env = &bpf_sandbox_env[prog_id];


	hash_for_each_possible(env->xdp_func_ht, a, hnode, (u64)fn) {
		if (a->addr == fn)
			return true;
	}

	return false;
}


void record_map_ops(u64 prog_id, const struct bpf_map_ops *ops)
{
	if (is_allowed_helper(prog_id, (u64)ops->map_lookup_elem))
		return;

	func_ht_add(prog_id, (u64)ops->map_lookup_elem);
	func_ht_add(prog_id, (u64)ops->map_update_elem);
	func_ht_add(prog_id, (u64)ops->map_delete_elem);
	func_ht_add(prog_id, (u64)ops->map_push_elem);
	func_ht_add(prog_id, (u64)ops->map_pop_elem);
	func_ht_add(prog_id, (u64)ops->map_peek_elem);
	func_ht_add(prog_id, (u64)ops->map_redirect);
	func_ht_add(prog_id, (u64)ops->map_for_each_callback);
	func_ht_add(prog_id, (u64)ops->map_lookup_percpu_elem);
}


u64 sandbox_tramp(void)
{
	u64 prog_id;

	volatile u64 call_target = bpf_sandbox_get_trampoline_target(&prog_id);


	if (unlikely(is_skb_helper(prog_id, call_target)) || unlikely(is_xdp_helper(prog_id, call_target))) {
		convert_bpf_ctx_to_kernel_ctx();
	}

//	if (prog_id != 33 && unlikely(!is_allowed_helper(prog_id, call_target))) {
//		return 0;
//	} 
	return bpf_sandbox_call_trampoline_target(call_target);

}
EXPORT_SYMBOL(sandbox_tramp);

void init_sandbox_env(void *env)
{
    struct bpf_verifier_env *v_env = (struct bpf_verifier_env *)env;
    struct bpf_sandbox_env *new_env; // 임시 포인터
    const struct bpf_func_proto *fn;
    u64 prog_id;
    int i;

    /* 1. 유효성 검사 (가장 중요) */
    if (!v_env || !v_env->prog) return;
    prog_id = v_env->prog->type;

    /* 2. 전역 변수 할당 로직 개선 */
    if (!bpf_sandbox_env) {
        new_env = kmalloc_array(MAX_BPF_PROG_TYPE, 
                                sizeof(struct bpf_sandbox_env), GFP_KERNEL);
        if (!new_env) return;

        for (i = 0; i < MAX_BPF_PROG_TYPE; i++) {
            hash_init(new_env[i].func_ht);
            hash_init(new_env[i].skb_func_ht);
            hash_init(new_env[i].xdp_func_ht);
        }
        /* 모든 루프가 끝난 '완성된' 상태에서만 대입 */
        bpf_sandbox_env = new_env; 
    }

    /* 3. 안전하게 참조 */
    if (prog_id < MAX_BPF_PROG_TYPE && hash_empty(bpf_sandbox_env[prog_id].func_ht)) {
        for (i = 0; i <= __BPF_FUNC_MAX_ID; i++) {
            fn = bpf_verifier_ops[prog_id]->get_func_proto(i, v_env->prog);
            if (!fn || !fn->func) continue;

            func_ht_add(prog_id, (u64)fn->func);
            skb_func_ht_add(i, prog_id, (u64)fn->func);
            xdp_func_ht_add(i, prog_id, (u64)fn->func);
        }
    }
}
