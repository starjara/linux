#include <linux/module.h>
#include <linux/verse_host.h>
#include <asm/page.h>

// Macros

#ifdef CONFIG_64BIT
static unsigned long gstage_mode __ro_after_init = (HGATP_MODE_SV39X4 << HGATP_MODE_SHIFT);
static unsigned long gstage_pgd_levels __ro_after_init = 3;
#define gstage_index_bits	9
#else
static unsigned long gstage_mode __ro_after_init = (HGATP_MODE_SV32X4 << HGATP_MODE_SHIFT);
static unsigned long gstage_pgd_levels __ro_after_init = 2;
#define gstage_index_bits	10
#endif

#define gstage_pgd_xbits	2
#define gstage_pgd_size	(1UL << (HGATP_PAGE_SHIFT + gstage_pgd_xbits))
#define gstage_gpa_bits	(HGATP_PAGE_SHIFT + \
			 (gstage_pgd_levels * gstage_index_bits) + \
			 gstage_pgd_xbits)
#define gstage_gpa_size	((gpa_t)(1ULL << gstage_gpa_bits))

#define gstage_pte_leaf(__ptep)	\
	(pte_val(*(__ptep)) & (_PAGE_READ | _PAGE_WRITE | _PAGE_EXEC))


// Functions
static inline unsigned long gstage_pte_index(gpa_t addr, u32 level)
{
  unsigned long mask;
  unsigned long shift = HGATP_PAGE_SHIFT + (gstage_index_bits * level);

  if (level == (gstage_pgd_levels - 1))
    mask = (PTRS_PER_PTE * (1UL << gstage_pgd_xbits)) - 1;
  else
    mask = PTRS_PER_PTE - 1;

  return (addr >> shift) & mask;
}

static inline unsigned long gstage_pte_page_vaddr(pte_t pte)
{
	return (unsigned long)pfn_to_virt(__page_val_to_pfn(pte_val(pte)));
}

static int gstage_level_to_page_order(u32 level, unsigned long *out_pgorder)
{
  if (gstage_pgd_levels < level)
    return -EINVAL;

  *out_pgorder = 12 + (level * gstage_index_bits);
  return 0;
}


static int gstage_level_to_page_size(u32 level, unsigned long *out_pgsize)
{
  int rc;
  unsigned long page_order = PAGE_SHIFT;

  rc = gstage_level_to_page_order(level, &page_order);
  if (rc)
    return rc;

  *out_pgsize = BIT(page_order);
  return 0;
}

static bool gstage_get_leaf_entry(struct verse *verse, gpa_t addr,
				  pte_t **ptepp, u32 *ptep_level)
{
  pte_t *ptep;
  u32 current_level = gstage_pgd_levels - 1;

  *ptep_level = current_level;
  ptep = (pte_t *)verse->arch.pgd;
  ptep = &ptep[gstage_pte_index(addr, current_level)];
  while (ptep && pte_val(*ptep)) {
    if (gstage_pte_leaf(ptep)) {
      *ptep_level = current_level;
      *ptepp = ptep;
      return true;
    }

    if (current_level) {
      current_level--;
      *ptep_level = current_level;
      ptep = (pte_t *)gstage_pte_page_vaddr(*ptep);
      ptep = &ptep[gstage_pte_index(addr, current_level)];
    } else {
      ptep = NULL;
    }
  }

  return false;
}

static void gstage_remote_tlb_flush(struct verse *verse, u32 level, gpa_t addr)
{
  unsigned long order = PAGE_SHIFT;

  if (gstage_level_to_page_order(level, &order))
    return;
  addr &= ~(BIT(order) - 1);

  //verse_riscv_hfence_gvma_vmid_gpa(verse, -1UL, 0, addr, BIT(order), order);
}

enum gstage_op {
  GSTAGE_OP_NOP = 0,	/* Nothing */
  GSTAGE_OP_CLEAR,	/* Clear/Unmap */
  GSTAGE_OP_WP,		/* Write-protect */
};

static void gstage_op_pte(struct verse *verse, gpa_t addr,
			  pte_t *ptep, u32 ptep_level, enum gstage_op op)
{
  int i, ret;
  pte_t *next_ptep;
  u32 next_ptep_level;
  unsigned long next_page_size, page_size;

  ret = gstage_level_to_page_size(ptep_level, &page_size);
  if (ret)
    return;

  BUG_ON(addr & (page_size - 1));

  if (!pte_val(*ptep))
    return;

  if (ptep_level && !gstage_pte_leaf(ptep)) {
    next_ptep = (pte_t *)gstage_pte_page_vaddr(*ptep);
    next_ptep_level = ptep_level - 1;
    ret = gstage_level_to_page_size(next_ptep_level,
				    &next_page_size);
    if (ret)
      return;

    if (op == GSTAGE_OP_CLEAR)
      set_pte(ptep, __pte(0));
    for (i = 0; i < PTRS_PER_PTE; i++)
      gstage_op_pte(verse, addr + i * next_page_size,
		    &next_ptep[i], next_ptep_level, op);
    if (op == GSTAGE_OP_CLEAR)
      put_page(virt_to_page(next_ptep));
  } else {
    if (op == GSTAGE_OP_CLEAR)
      set_pte(ptep, __pte(0));
    else if (op == GSTAGE_OP_WP)
      set_pte(ptep, __pte(pte_val(*ptep) & ~_PAGE_WRITE));
    //gstage_remote_tlb_flush(verse, ptep_level, addr);
  }
}

static void gstage_unmap_range(struct verse *verse, gpa_t start,
			       gpa_t size, bool may_block)
{
  int ret;
  pte_t *ptep;
  u32 ptep_level;
  bool found_leaf;
  unsigned long page_size;
  gpa_t addr = start, end = start + size;

  while (addr < end) {
    found_leaf = gstage_get_leaf_entry(verse, addr,
				       &ptep, &ptep_level);
    ret = gstage_level_to_page_size(ptep_level, &page_size);
    if (ret)
      break;

    if (!found_leaf)
      goto next;

    if (!(addr & (page_size - 1)) && ((end - addr) >= page_size))
      gstage_op_pte(verse, addr, ptep,
		    ptep_level, GSTAGE_OP_CLEAR);

  next:
    addr += page_size;

    /*
     * If the range is too large, release the verse->mmu_lock
     * to prevent starvation and lockup detector warnings.
     */
    if (may_block && addr < end)
      cond_resched_lock(&verse->mmu_lock);
  }
}


int verse_riscv_gstage_alloc_pgd(struct verse *verse)
{
  struct page *pgd_page;

  if (verse->arch.pgd != NULL) {
    verse_error("\t\t[verse_arch] verse_arch already initialized?\n");
    return -EINVAL;
  }

  pgd_page = alloc_pages(GFP_KERNEL | __GFP_ZERO,
			 get_order(gstage_pgd_size));
  if (!pgd_page)
    return -ENOMEM;
  verse->arch.pgd = page_to_virt(pgd_page);
  verse->arch.pgd_phys = page_to_phys(pgd_page);

  return 0;
}

void verse_riscv_gstage_free_pgd(struct verse *verse)
{
  void *pgd = NULL;

  spin_lock(&verse->mmu_lock);
  if (verse->arch.pgd) {
    gstage_unmap_range(verse, 0UL, gstage_gpa_size, false);
    verse->arch.pgd = NULL;
    pgd = READ_ONCE(verse->arch.pgd);
    verse->arch.pgd_phys = 0;
  }
  spin_unlock(&verse->mmu_lock);
  
  if (pgd)
    free_pages((unsigned long)pgd, get_order(gstage_pgd_size));
}

void verse_riscv_gstage_update_hgatp(struct verse *verse)
{
  unsigned long hgatp = gstage_mode;
  struct verse_arch *k = &(verse->arch);
  unsigned long current_hgatp = csr_read(CSR_HGATP);

  hgatp |= (READ_ONCE(k->vmid.vmid) << HGATP_VMID_SHIFT) & HGATP_VMID;
  hgatp |= (k->pgd_phys >> PAGE_SHIFT) & HGATP_PPN;

  if (current_hgatp != hgatp) {
    csr_write(CSR_HGATP, hgatp);

    if(!verse_riscv_gstage_vmid_bits())
      asm volatile(HFENCE_GVMA(zero, zero) : : : "memory");
  }
}

void verse_arch_flush_shadow_all(struct verse *verse)
{
  verse_riscv_gstage_free_pgd(verse);
}
