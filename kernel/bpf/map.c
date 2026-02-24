/* Garden Start : Copying SafeBPF */

#include <linux/hashtable.h>
#include <linux/bpf_map.h>

struct bpf_map_env {
	DECLARE_HASHTABLE(active_map_ht, 4);
	DECLARE_HASHTABLE(lookup_func_ht, 4);
};

struct bpf_map_entry {
	u64 addr;
	struct hlist_node hnode;
};

struct bpf_lookup_func_entry {
	u64 addr;
	struct hlist_node hnode;
};

static struct bpf_map_env *bpf_map_env;

void bpf_sandbox_add_map(struct bpf_map *map)
{
	struct bpf_map_entry *e;

	e = kzalloc(sizeof(struct bpf_map_entry), GFP_ATOMIC);
	if (!e)
		return;

	e->addr = (u64)map;
	hash_add(bpf_map_env->active_map_ht, &e->hnode, (u64)map);

	pr_info("BPF: Added map %llx to ht", (u64)map);
}
EXPORT_SYMBOL(bpf_sandbox_add_map);

void bpf_sandbox_delete_map(struct bpf_map *map)
{
	int i;
	struct hlist_node *tmp;
	struct bpf_map_entry *e;

	hash_for_each_safe(bpf_map_env->active_map_ht, i, tmp, e, hnode) {
		if (e->addr == (u64)map) {
			hash_del(&e->hnode);
			kfree(e);
			pr_info("BPF: Deleted map %llx from ht", (u64)map);
			return;
		}
	}
}
EXPORT_SYMBOL(bpf_sandbox_delete_map);

void bpf_sandbox_add_map_lookup(const struct bpf_map_ops *ops)
{
	struct bpf_lookup_func_entry *e;
	u64 lookup_fn = (u64)ops->map_lookup_elem;

	if(lookup_fn && !is_map_lookup(lookup_fn)) {
		e = kzalloc(sizeof(struct bpf_lookup_func_entry), GFP_ATOMIC);
		if (!e)
			return;
		e->addr = lookup_fn;
		hash_add(bpf_map_env->lookup_func_ht, &e->hnode, lookup_fn);
	}
}
EXPORT_SYMBOL(bpf_sandbox_add_map_lookup);

bool is_active_map(u64 map)
{
	struct bpf_map_entry *e;

	hash_for_each_possible(bpf_map_env->active_map_ht, e, hnode, map) {
		if(e->addr == map)
			return true;
	}
	return false;
}
EXPORT_SYMBOL(is_active_map);

bool is_map_lookup(u64 fn)
{
	struct bpf_lookup_func_entry *e;

	hash_for_each_possible(bpf_map_env->lookup_func_ht, e, hnode, fn) {
		if(e->addr == fn)
			return true;
	}

	return false;
}
EXPORT_SYMBOL(is_map_lookup);

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






