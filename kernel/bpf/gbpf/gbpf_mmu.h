#ifndef __GBPF_MMU_H__
#define __GBPF_MMU_H__

static int gbpf_alloc_gpgd(struct bpf_prog *prog);
static void gbpf_free_gpgd(struct bpf_prog *prog);
static void *gbpf_alloc_table(void);


void gbpf_free_all_levels(void *table, int level);
void gbpf_init_basic_mappings(struct bpf_prog *prog);
int gbpf_create_pgtable(struct bpf_prog *);
void gbpf_destroy_pgtable(struct bpf_prog *);
pte_t *gbpf_get_pte_ptr(void *gpgd, unsigned long vaddr);


#endif /* __GBPF_MMU_H__ */
