// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 University of British Columbia
 *
 * Author: Soo Yee Lim <sooyee@cs.ubc.ca>
 */

#include <linux/hashtable.h>
#include <linux/bpf_map.h>

#ifdef CONFIG_BPF_SFI_MAP_MASKING

/**
 * struct bpf_map_env - sandbox environment for bpf maps
 *
 * Each bpf_map_env structre delcares a hashtable named active_map_ht
 * with 16 buckets, and lookup_func_ht with 16 buckets.
 */
struct bpf_map_env {
	DECLARE_HASHTABLE(active_map_ht, 4);          // 16 buckets
	DECLARE_HASHTABLE(lookup_func_ht, 4);          // 16 buckets
};

/**
 * struct bpf_map_entry - defines an entry in the active map hash table
 *
 * @addr: address of struct bpf_map
 * @hnode: hashable node to link helper function to the function hashtable
 *
 * Every active bpf map has an address of its struct bpf_map and
 * a hashable node that allows the map entry to be added to
 * the hashtable of currently active maps.
 */
struct bpf_map_entry {
	u64			addr;
	struct hlist_node	hnode;
};

/**
 * struct bpf_lookup_func_entry - defines an entry in the lookup function
 *								  hash table
 *
 * @addr: address of lookup function
 * @hnode: hashable node to link helper function to the function hashtable
 *
 * Every active bpf map has an address of its lookup function and
 * a hashable node that allows the map entry to be added to
 * the hashtable of map lookup functions. Note that we only record lookups
 * because that is the only map operation that returns a pointer to the
 * map value (which we need to mask).
 */
struct bpf_lookup_func_entry {
	u64			addr;
	struct hlist_node	hnode;
};

static struct bpf_map_env *bpf_map_env;

/**
 * bpf_sandbox_add_map() - add a map to hash table
 *
 * @map: pointer to struct bpf_map
 *
 * Stores the address of the maps, to be invoked during map creation.
 * During JIT compilation, we search the hash table to determine if
 * an imm64 is a map.
 */
void bpf_sandbox_add_map(struct bpf_map *map)
{
	struct bpf_map_entry *e;

	e = kzalloc(sizeof(struct bpf_map_entry), GFP_ATOMIC);
	if (!e)
		return;

	e->addr = (u64)map;
	hash_add(bpf_map_env->active_map_ht, &e->hnode, (u64)map);

	// pr_info("BPF: Added map %llx to ht", (u64)map);
}
EXPORT_SYMBOL(bpf_sandbox_add_map);

/**
 * bpf_sandbox_delete_map() - delete a map from hash table
 *
 * @map: pointer to struct bpf_map
 *
 * Deletes the map entry, to be invoked during map free.
 */
void bpf_sandbox_delete_map(struct bpf_map *map)
{
	int i;
	struct hlist_node *tmp;
	struct bpf_map_entry *e;

	hash_for_each_safe(bpf_map_env->active_map_ht, i, tmp, e, hnode) {
		if (e->addr == (u64)map) {
			hash_del(&e->hnode);
			kfree(e);
			// pr_info("BPF: Deleted map %llx from ht", (u64)map);
			return;
		}
	}
}
EXPORT_SYMBOL(bpf_sandbox_delete_map);

/**
 * bpf_sandbox_add_map_lookup() - add a map lookup func to hash table
 *
 * @ops: a struct containing all the operations for a map type
 *
 * Stores the address of the lookup function, to be invoked when
 * the verifier is doing post-verification fixups. During JIT
 * compilation, once a map lookup function is called, the return
 * register will need special map masking.
 */
void bpf_sandbox_add_map_lookup(const struct bpf_map_ops *ops)
{
	struct bpf_lookup_func_entry *e;
	u64 lookup_fn = (u64)ops->map_lookup_elem;

	if (lookup_fn && !is_map_lookup(lookup_fn)) {
		e = kzalloc(sizeof(struct bpf_lookup_func_entry), GFP_ATOMIC);
		if (!e)
			return;

		e->addr = lookup_fn;
		hash_add(bpf_map_env->lookup_func_ht, &e->hnode, lookup_fn);
		// pr_info("BPF: Added lookup func %llx to ht, is_map_lookup = %d",
					// lookup_fn, is_map_lookup(lookup_fn));
	}

}
EXPORT_SYMBOL(bpf_sandbox_add_map_lookup);

/**
 * is_active_map() - checks if a map is currently active
 *
 * @addr: address of struct bpf_map
 *
 * To be called by the JIT compiler to check if an imm64 is
 * an active map.
 */
bool is_active_map(u64 map)
{
	struct bpf_map_entry *e;

	hash_for_each_possible(bpf_map_env->active_map_ht, e, hnode, map) {
		if (e->addr == map)
			return true;
	}

	return false;
}
EXPORT_SYMBOL(is_active_map);

/**
 * is_map_lookup() - checks if a given function is a
 *					 map lookup function.
 *
 * @fn: 64-bit address of a function
 *
 * To be called by the JIT compiler to check if the eBPF
 * program is calling a map lookup function.
 */
bool is_map_lookup(u64 fn)
{
	struct bpf_lookup_func_entry *e;

	hash_for_each_possible(bpf_map_env->lookup_func_ht, e, hnode, fn) {
		if (e->addr == fn)
			return true;
	}

	return false;
}
EXPORT_SYMBOL(is_map_lookup);

/**
 * init_bpf_map_env() - initializes the hash tables for eBPF maps
 */
static int __init init_bpf_map_env(void)
{
	bpf_map_env = kmalloc(sizeof(struct bpf_map_env), GFP_ATOMIC);
	if (bpf_map_env) {
		hash_init(bpf_map_env->lookup_func_ht);
		hash_init(bpf_map_env->active_map_ht);
	}
	pr_info("BPF Sandbox: htabs for map initialized at %llx", (u64)bpf_map_env);
	return 0;
}

core_initcall(init_bpf_map_env);

#endif /* CONFIG_BPF_SFI_MAP_MASKING */
