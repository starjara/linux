#ifndef __GBPF_MMU_H__
#define __GBPF_MMU_H__

static int gbpf_alloc_gpgd(struct bpf_prog *prog);
static void gbpf_free_gpgd(struct bpf_prog *prog);
static void *gbpf_alloc_table(void);
struct page *gbpf_map_private_data(struct bpf_prog *prog, unsigned long vaddr);
static int gbpf_map_preallocated_page(struct bpf_prog *prog, unsigned long vaddr, struct page *page);


int gbpf_run_prepare(struct bpf_prog *prog, struct pt_regs *regs);
void setup_execution_context(struct page *private_page, struct pt_regs *regs, u32 prog_id);
void gbpf_free_all_levels(void *table, int level);
void gbpf_init_basic_mappings(struct bpf_prog *prog);
int gbpf_create_pgtable(struct bpf_prog *);
void gbpf_destroy_pgtable(struct bpf_prog *);
pte_t *gbpf_get_pte_ptr(void *gpgd, unsigned long vaddr);


#endif /* __GBPF_MMU_H__ */
