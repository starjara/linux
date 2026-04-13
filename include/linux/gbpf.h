#ifndef _LINUX_GBPF_H
#define _LINUX_GBPF_H

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/netdevice.h>
#include <net/xdp.h>

#define GBPF_PAGE_SIZE 4096
#define GBPF_CONTEXT_SIZE 512
#define GBPF_STACK_SIZE (GBPF_PAGE_SIZE - GBPF_CONTEXT_SIZE)

#define GBPF_CTX_BASE 0x80000000ULL
#define GBPF_PKT_BASE 0x90000000ULL
#define GBPF_PKT_MAX_PAGES  64
#define GBPF_MAP_BASE 0xA0000000ULL

#define GBPF_MAP_WINDOW_SIZE 0x01000000UL   /* 16MB per map */
#define GBPF_CPU_WINDOW_SIZE 0x00100000UL   /* 64KB per cpu */

#define GBPF_STK_SAVE_S11       0
#define GBPF_STK_SAVE_S10       8
#define GBPF_STK_SAVE_S9       16
#define GBPF_STK_OLD_HGATP     24
#define GBPF_TR_FRAME_SIZE     32
/*
#define GBPF_STK_CTX_BASE      24
#define GBPF_STK_PKT_BASE      32
#define GBPF_STK_MAP_BASE      40
#define GBPF_ORG_CTX           48
#define GBPF_STK_PROG_TYPE     56
#define GBPF_TR_FRAME_SIZE     64
*/


struct page;


struct gbpf_map_desc {
	struct bpf_map *map;
	u32 map_slot;
	bool percpu;

	/* non-percpu base */
	u64 base;

	/* percpu base for each cpu */
	u64 percpu_base[NR_CPUS];
};

extern size_t gbpf_ctx_size_map[];

enum GBPF_MAP_TYPE {
  PKT,
  MAP,
  PERCPU_MAP,
};

struct gbpf_ops {
  int (*check_module)(void);
  int (*create_pgd)(struct bpf_prog *prog);
  int (*map)(struct bpf_prog *prog);
  int (*map_ext)(const struct bpf_prog *prog, const void *kaddr, size_t len, enum GBPF_MAP_TYPE type, int map_num, int cpu);
  void (*destroy_pgtable)(struct bpf_prog *prog);
  u32 (*get_vmid)(void);
  void (*inc_vmid)(void);
  void (*dec_vmid)(void);
};

// Module call related 
int gbpf_register_ops(const struct gbpf_ops *ops);
void gbpf_unregister_ops(const struct gbpf_ops *ops);

const struct gbpf_ops *pbpf_ops_get(void);

// Module functions
int gbpf_call_check_module(void);
int gbpf_call_create_pgd(struct bpf_prog *prog);
int gbpf_call_map(struct bpf_prog *prog);
int gbpf_call_map_ext(const struct bpf_prog *prog, const void *kaddr, size_t len, enum GBPF_MAP_TYPE type, int map_num, int cpu);
void gbpf_call_destroy_pgtable(struct bpf_prog *prog);
u32 gbpf_call_get_vmid(void);
void gbpf_call_inc_vmid(void);
void gbpf_call_dec_vmid(void);
void *gbpf_copy_ctx(const void *ctx, const struct bpf_prog *prog);

// Trampoline functions
u64 gbpf_helper_call_trampoline(u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5);

// Map functions
int gbpf_try_encode_kernel_map_ptr(u64 kptr, struct bpf_prog *prog, u64 *out);
int gbpf_init_prog_map_descs(struct bpf_prog *prog);


static inline u64 gbpf_encode_map_addr(u32 map_slot, u32 cpu_slot, u64 offset)
{
	return GBPF_MAP_BASE +
	       (u64)map_slot * GBPF_MAP_WINDOW_SIZE +
	       (u64)cpu_slot * GBPF_CPU_WINDOW_SIZE +
	       offset;
}

static inline int gbpf_decode_map_addr(u64 addr, u32 *map_slot,
				       u32 *cpu_slot, u32 *offset)
{
	u32 delta, rem;

	if (addr < GBPF_MAP_BASE)
		return -EINVAL;

	delta = addr - GBPF_MAP_BASE;
	*map_slot = delta / GBPF_MAP_WINDOW_SIZE;
	rem = delta % GBPF_MAP_WINDOW_SIZE;
	*cpu_slot = rem / GBPF_CPU_WINDOW_SIZE;
	*offset = rem % GBPF_CPU_WINDOW_SIZE;
	return 0;
}

#endif /* _LINUX_GBPF_H  */
