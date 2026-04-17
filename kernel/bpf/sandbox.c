// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 University of British Columbia
 *
 * Author: Soo Yee Lim <sooyee@cs.ubc.ca>
 */
#include <linux/cpu.h>
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/bpf_sandbox.h>
#include <linux/skmsg.h>
#include <linux/perf_event.h>
#include "disasm.h"


extern u64 bpf_skb_load_helper_8_no_cache(const struct sk_buff *skb, int offset);
extern u64 bpf_skb_load_helper_16_no_cache(const struct sk_buff *skb, int offset);
extern u64 bpf_skb_load_helper_32_no_cache(const struct sk_buff *skb, int offset);

/**
 * struct bpf_sandbox_env - sandbox environment for bpf program types
 *
 * Each bpf_sandbox_env structre delcares a hashtable named func_ht
 * with 128 buckets, and a skb_func_ht with 16 buckets, and a
 * xdp_func_ht with 16 buckets.
 */
struct bpf_sandbox_env {
	DECLARE_HASHTABLE(func_ht, 7);          // 128 buckets
	DECLARE_HASHTABLE(skb_func_ht, 4);      // 16 buckets
	DECLARE_HASHTABLE(xdp_func_ht, 2);      // 2 buckets
};

/**
 * struct bpf_helper - defines a bpf helper function
 *
 * @addr: address of the helper function
 * @hnode: hashable node to link helper function to the function hashtable
 *
 * Every allowed bpf helper function has an address of where it is stored in
 * memory and a hashable node that allows the helper function to be added to
 * the hashtable of allowed functions for a given bpf program type.
 */
struct bpf_helper {
	u64			addr;
	struct hlist_node	hnode;
};

static struct bpf_sandbox_env *bpf_sandbox_env;

/**
 * struct bpf_verifier_ops - stores the verifier operations associated with each bpf program type
 */
static const struct bpf_verifier_ops *const bpf_verifier_ops[] = {
#define BPF_PROG_TYPE(_id,		 _name, prog_ctx_type, kern_ctx_type) \
	[_id] = &_name ## _verifier_ops,
#define BPF_MAP_TYPE(_id,		 _ops)
#define BPF_LINK_TYPE(_id,		 _name)
#include <linux/bpf_types.h>
#undef BPF_PROG_TYPE
#undef BPF_MAP_TYPE
#undef BPF_LINK_TYPE
};

/**
 * bpf_ctx_size_map - stores the context size associated with each bpf program type
 */
size_t bpf_ctx_size_map[] = {
#define BPF_PROG_TYPE(_id,	       _name, prog_ctx_type, kern_ctx_type) \
	[_id] = sizeof(kern_ctx_type),
#define BPF_MAP_TYPE(_id,	       _ops)
#define BPF_LINK_TYPE(_id,	       _name)
#include <linux/bpf_types.h>
#undef BPF_PROG_TYPE
#undef BPF_MAP_TYPE
#undef BPF_LINK_TYPE
	0,                             /* avoid empty array */
};
EXPORT_SYMBOL(bpf_ctx_size_map);

/**
 * is_allowed_helper() - checks if a helper function is allowed
 *
 * @prog_id: program type identifier
 * @fn: helper function
 *
 * Iterates over all functions in the function hash table for the bpf sandbox
 * environment specific to the passed program id and checks if the value of
 * the passed helper function is equal to any functions defined in the
 * hashtable. If it is equal then this function is an allowed helper function in
 * the bpf sandbox environment for the specified program id.
 *
 * Return: Returns true if fn is an allowed helper function in the specified bpf
 *         sandbox environment. Otherwise, returns false.
 */
static __always_inline bool is_allowed_helper(u64 prog_id, u64 fn)
{
	struct bpf_helper *a;

	hash_for_each_possible(bpf_sandbox_env[prog_id].func_ht, a, hnode, fn) {
		if (a->addr == fn)
			return true;
	}

	return false;
}

/**
 * is_skb_helper() - checks if a helper function takes sk_buff as its argument
 *
 * @prog_id: program type identifier
 * @fn: helper function
 *
 * Iterates over all functions in the skb function hash table for the bpf sandbox
 * environment specific to the passed program id and checks if the value of
 * the passed helper function is equal to any functions defined in the
 * hashtable. If it is equal then this function is an allowed helper function in
 * the bpf sandbox environment for the specified program id.
 *
 * Return: Returns true if fn is an allowed helper function in the specified bpf
 *         sandbox environment. Otherwise, returns false.
 */
static __always_inline bool is_skb_helper(u64 prog_id, u64 fn)
{
	struct bpf_helper *a;

	hash_for_each_possible(bpf_sandbox_env[prog_id].skb_func_ht, a, hnode, fn) {
		if (a->addr == fn)
			return true;
	}

	return false;
}

/**
 * is_xdp_helper() - checks if a helper function takes xdp_buff as its argument
 *
 * @prog_id: program type identifier
 * @fn: helper function
 *
 * Iterates over all functions in the xdp function hash table for the bpf sandbox
 * environment specific to the passed program id and checks if the value of
 * the passed helper function is equal to any functions defined in the
 * hashtable. If it is equal then this function is an allowed helper function in
 * the bpf sandbox environment for the specified program id.
 *
 * Return: Returns true if fn is an allowed helper function in the specified bpf
 *         sandbox environment. Otherwise, returns false.
 */
static __always_inline bool is_xdp_helper(u64 prog_id, u64 fn)
{
	struct bpf_helper *a;

	hash_for_each_possible(bpf_sandbox_env[prog_id].xdp_func_ht, a, hnode, fn) {
		if (a->addr == fn)
			return true;
	}

	return false;
}

/**
 * sandbox_tramp() - checks validity of helper function before calling
 *
 * Receives the call target which is the address of the helper function then
 * determines if the call target is an allowed helper function of the specified
 * bpf sandbox environment. If the helper function is determined to be valid,
 * the helper function is called.
 */
#ifdef CONFIG_X86_64
u64 sandbox_tramp(void)
{
	u64 prog_id;
	volatile u64 call_target = bpf_sandbox_get_trampoline_target(&prog_id);

#ifdef CONFIG_BPF_SANDBOX_CTX
	if (unlikely(is_skb_helper(prog_id, call_target)) ||
		unlikely(is_xdp_helper(prog_id, call_target)))
		convert_bpf_ctx_to_kernel_ctx();
#endif /* CONFIG_BPF_SANDBOX_CTX */

#ifdef CONFIG_BPF_SFI_TRAMPOLINE
	// Don't proceed if it's not a valid helper function
	if (unlikely(!is_allowed_helper(prog_id, call_target)))
		return 0;
#endif /* CONFIG_BPF_SFI_TRAMPOLINE */

	// Call the valid helper function
	return bpf_sandbox_call_trampoline_target(call_target);

	// TODO: if the helper function writes to fields accesible by __sk_buff,
	//		 synchronize the changes back to __sk_buff
}
#endif

#ifdef CONFIG_ARM64
void sandbox_tramp(volatile u64 r1, volatile u64 r2, volatile u64 r3, volatile u64 r4,
		   volatile u64 r5)
{
	u64 prog_id;
	volatile u64 call_target = bpf_sandbox_get_trampoline_target(&prog_id);

#ifdef CONFIG_BPF_SANDBOX_CTX
	if (unlikely(is_skb_helper(prog_id, call_target)) ||
		unlikely(is_xdp_helper(prog_id, call_target)))
		convert_bpf_ctx_to_kernel_ctx(&r1);
#endif /* CONFIG_BPF_SANDBOX_CTX */

#ifdef CONFIG_BPF_SFI_TRAMPOLINE
	// Don't proceed if it's not a valid helper function
	if (unlikely(!is_allowed_helper(prog_id, call_target)))
		return;
#endif /* CONFIG_BPF_SFI_TRAMPOLINE */

	// Call the valid helper function
	bpf_sandbox_call_trampoline_target(call_target, r1, r2, r3, r4, r5);
}
EXPORT_SYMBOL(sandbox_tramp);
#endif


#ifdef CONFIG_ARCH_RV64I
void sandbox_tramp(volatile u64 r1, volatile u64 r2, volatile u64 r3, volatile u64 r4,
		   volatile u64 r5)
{
	u64 prog_id;
	volatile u64 call_target = bpf_sandbox_get_trampoline_target(&prog_id);

#ifdef CONFIG_BPF_SANDBOX_CTX
	if (unlikely(is_skb_helper(prog_id, call_target)) ||
		unlikely(is_xdp_helper(prog_id, call_target)))
		convert_bpf_ctx_to_kernel_ctx(&r1);
	
	if (call_target == (u64)bpf_skb_load_helper_8_no_cache) {
		convert_bpf_ctx_to_kernel_ctx(&r1);
		pr_info("ctx converted\n");
	}
#endif /* CONFIG_BPF_SANDBOX_CTX */

#ifdef CONFIG_BPF_SFI_TRAMPOLINE
	// Don't proceed if it's not a valid helper function
	if (unlikely(!is_allowed_helper(prog_id, call_target)))
		return;
#endif /* CONFIG_BPF_SFI_TRAMPOLINE */

	// Call the valid helper function
	bpf_sandbox_call_trampoline_target(call_target, r1, r2, r3, r4, r5);
}
EXPORT_SYMBOL(sandbox_tramp);
#endif

/**
 * func_ht_add - adds a function to the hashtable of allowed helper functions
 *
 * @prog_id: program type identifier
 * @fn: helper function
 *
 * Adds the new function, fn, to the hashtable of allowed helper functions
 * for the bpf sandbox environment for the specified program type.
 */
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

/**
 * skb_func_ht_add - adds a function that takes sk_buff as its argument
 *					 to the hashtable
 *
 * @i: function id
 * @prog_id: program type identifier
 * @fn: helper function
 *
 * Adds the new function, fn, to the hashtable of skb helper functions
 * for the bpf sandbox environment for the specified program type.
 */
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
	case BPF_FUNC_sk_assign:                 // needs additional synchronization?
	case BPF_FUNC_csum_level:
	case BPF_FUNC_skb_cgroup_classid:
	case BPF_FUNC_skb_set_tstamp:                 // needs additional synchronization?
		a = kzalloc(sizeof(struct bpf_helper), GFP_ATOMIC);
		if (!a)
			return;
		a->addr = fn;
		hash_add(bpf_sandbox_env[prog_id].skb_func_ht, &a->hnode, fn);
		break;
	}
}

/**
 * xdp_func_ht_add - adds a function that takes xdp_buff as its argument
 *					 to the hashtable
 *
 * @i: function id
 * @prog_id: program type identifier
 * @fn: helper function
 *
 * Adds the new function, fn, to the hashtable of xdp helper functions
 * for the bpf sandbox environment for the specified program type.
 */
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

/**
 * record_map_ops() - Keeps track of valid map operations (for CFI)
 *
 * @prog_id: program type identifier
 * @ops: a struct containing all the operations for a particular map type
 *
 * Each map type has their own implementation of map functions, which is not
 * captured by init_sandbox_env (i.e., just iterating through
 * [prog_type]_func_proto in bpf_verifier_ops). This function is to be called
 * in the verifier's post-verification fixup, recording the map operations of
 * every map type in the eBPF program.
 */
void record_map_ops(u64 prog_id, const struct bpf_map_ops *ops)
{
	// If either one of the map ops is already recorded, return
	// because we already have all the ops for this map type
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


/**
 * init_sandbox_env() - initializes sandbox environments
 *
 * @env: bpf verification environment
 *
 * For each bpf program type, a sandbox environment is initialized. Then the
 * function hashtable of allowed helper functions for each program type is
 * created. Finally, the helper functions obtained from the verifier at compile
 * time are stored in the function hashtable for each bpf sandbox environment
 * type.
 */
void init_sandbox_env(void *env)
{
	const struct bpf_verifier_env *verifier_env = env;
	const struct bpf_func_proto *fn;
	u64 prog_id = verifier_env->prog->type;

	// Initialize sandbox_env
	if (!bpf_sandbox_env) {
		bpf_sandbox_env = kmalloc_array(MAX_BPF_PROG_TYPE,
						sizeof(struct bpf_sandbox_env), GFP_KERNEL);
		for (int i = 0; i < MAX_BPF_PROG_TYPE; i++) {
			hash_init(bpf_sandbox_env[i].func_ht);
			hash_init(bpf_sandbox_env[i].skb_func_ht);
			hash_init(bpf_sandbox_env[i].xdp_func_ht);
		}
	}

	if (hash_empty(bpf_sandbox_env[prog_id].func_ht)) {
		// Store the helper function addresses to a hashtable
		for (int i = 0; i <= __BPF_FUNC_MAX_ID; i++) {
			fn = bpf_verifier_ops[prog_id]->get_func_proto(i, verifier_env->prog);
			if (!fn)
				continue;
			func_ht_add(prog_id, (u64)fn->func);
			skb_func_ht_add(i, prog_id, (u64)fn->func);
			xdp_func_ht_add(i, prog_id, (u64)fn->func);

			// TEST
			// pr_info("prog_type = %lld, func_id_name = %s, fn64 = %llx",
			//	prog_id, func_id_name(i), (u64)fn->func);
			// pr_info("is_allowed_helper = %d, is_skb_helper = %d",
			//	is_allowed_helper(prog_id, (u64)fn->func),
			//	is_skb_helper(prog_id, (u64)fn->func));
			// pr_info("is_xdp_helper = %d", is_xdp_helper(prog_id, (u64)fn->func));
		}
	}
}

union bpf_sandbox *sandboxes;
EXPORT_SYMBOL(sandboxes);

uintptr_t bpf_sandbox_and_mask;
EXPORT_SYMBOL(bpf_sandbox_and_mask);

void *sandbox_ctx;
EXPORT_SYMBOL(sandbox_ctx);

/**
 * init_bpf_sandbox() - sets up sandbox management
 *
 * Initializes sandbox management by allocating memory for sandbox
 * instances. If a problem occurs with memory allocation, kernel panic occurs
 * and status is shown through log messages. Finally, address masks are
 * generated and stored.
 */
static int __init init_bpf_sandbox(void)
{
	pr_info("BPF Sandbox: Core %d initializing sandbox management ...", smp_processor_id());
	sandboxes = kmalloc(BPF_SANDBOX_TOTAL_SIZE * nr_cpu_ids, GFP_ATOMIC);
	pr_info("BPF Sandbox: Core %d initializing sandbox management at %px ...", smp_processor_id(), sandboxes);
	if (!sandboxes)
		panic("BPF Sandbox: could not allocate sandboxes");

	bpf_sandbox_and_mask = gen_and_mask(BPF_SANDBOX_SIZE);
	for (int i = 0; i < nr_cpu_ids; i++) {
		sandboxes[i].info.or_mask = gen_or_mask(sandboxes[i].mem.private, BPF_SANDBOX_SIZE);
#ifdef CONFIG_BPF_SANDBOX_MTE
		bpf_mte_tag_mem(bpf_mte_set_tag(sandboxes[i].mem.private, BPF_MTE_TAG_SANDBOX),
				BPF_SANDBOX_SIZE, true);
#endif                 /* CONFIG_BPF_SANDBOX_MTE */
	}

	pr_info("BPF Sandbox: sandbox management initialized.");
	return 0;
}

core_initcall(init_bpf_sandbox);

void record_jit_helper_target(u64 prog_id, u64 fn)
{
    if (!fn)
        return;

    if (is_allowed_helper(prog_id, fn))
        return;

    func_ht_add(prog_id, fn);
}
EXPORT_SYMBOL(record_jit_helper_target);
