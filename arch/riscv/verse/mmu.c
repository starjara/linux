#include <linux/module.h>
#include <linux/verse_host.h>

#include <linux/hugetlb.h>

#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/slab.h>

#include <linux/uaccess.h>
// Macros
// #define LOG_E verse_info("\t[riscv/mmu.c] Enter: %s\n", __func__);
#define LOG_E 

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


static pte_t *verse_riscv_print_pgtable(struct verse *verse, unsigned long addr, bool guest) 
{
  pte_t *pgd;
  pte_t *pte;
  pte_t *next_pte;
  int current_level = gstage_pgd_levels - 1;;

  //verse_info("[verse] print page table entries for 0x%lx ", addr);
  
  if(guest != 0) {
    //pgd = phys_to_virt((csr_read(CSR_HGATP) & 0xFFFFF) << PAGE_SHIFT);
    pgd = (pte_t *)verse->arch.pgd;
    //verse_info("in guest machine\n");
  }
  else {
    pgd = phys_to_virt((csr_read(CSR_SATP) & 0xFFFFF) << PAGE_SHIFT);
    //verse_info("in host machine\n");
  }

  pte = &pgd[gstage_pte_index(addr, current_level--)];
  //verse_info("[verse] [%d] pgd 0x%lx\t0x%lx\n", current_level+1, pgd, *pte);

  while(current_level >= 0) {
    next_pte = (pte_t *)gstage_pte_page_vaddr(*pte);
    pte = &next_pte[gstage_pte_index(addr, current_level--)];
    //verse_info("[verse] [%d] pte 0x%lx\t0x%lx\n", current_level+1, next_pte, *pte);
  }

  /*
  if(guest == 0) {
    //pte->pte = pte->pte & 0xFFFFFFFFFFFFFFFB;
    //set_pte(pte, pte->pte);
    set_pte(pte, __pte(pte_val(*pte) & ~_PAGE_WRITE));
    //set_pte(ptep, __pte(pte_val(*ptep) & ~_PAGE_WRITE));
  }
  */
  

  return pte;
}

static int gstage_page_size_to_level(unsigned long page_size, u32 *out_level)
{
	u32 i;
	unsigned long psz = 1UL << 12;

	for (i = 0; i < gstage_pgd_levels; i++) {
		if (page_size == (psz << (i * gstage_index_bits))) {
			*out_level = i;
			return 0;
		}
	}

	return -EINVAL;
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
    asm volatile(HFENCE_GVMA(zero, zero) : : : "memory");
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

  LOG_E
  
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

static int gstage_set_pte(struct verse *verse, u32 level,
			  gpa_t addr, const pte_t *new_pte)
{
  u32 current_level = gstage_pgd_levels - 1;
  pte_t *next_ptep = (pte_t *)verse->arch.pgd;
  pte_t *ptep = &next_ptep[gstage_pte_index(addr, current_level)];

  if(current_level < level) {
    verse_error("\t\t[verse_arch] level error\n");
    return -EINVAL;
  }

  while (current_level != level) {
    if(gstage_pte_leaf(ptep)) {
      verse_error("\t\t[verse_arch] Leaf PTE alraedy exist 0x%lx\n", *ptep);
      return -EEXIST;
    }

    if(!pte_val(*ptep)) {
      //next_ptep = __get_free_page(GFP_ATOMIC | __GFP_ACCOUNT);
      //next_ptep = page_to_virt(alloc_page(GFP_ATOMIC | __GFP_ACCOUNT));
      next_ptep = get_zeroed_page(GFP_ATOMIC | __GFP_ACCOUNT);
      
      if (!next_ptep) {
	verse_error("\t\t[verse_arch] Failed to get a new page\n");
	return -ENOMEM;
      }
      *ptep = pfn_pte(PFN_DOWN(__pa(next_ptep)), __pgprot(_PAGE_TABLE));
    }
    else {
      if(gstage_pte_leaf(ptep)) {
	verse_error("\t\t[verse_arch] PTE alraedy exist 0x%lx\n", *ptep);
	return -EEXIST;
      }

      next_ptep = (pte_t *)gstage_pte_page_vaddr(*ptep);
    }

    current_level --;
    ptep = &next_ptep[gstage_pte_index(addr, current_level)];
  }

  *ptep = *new_pte;

  if(gstage_pte_leaf(ptep)) {
      asm volatile(HFENCE_GVMA(zero, zero) : : : "memory");
      //asm volatile("sfence.vma" ::: "memory");
  }
  
  return 0;
}

static int gstage_map_page(struct verse *verse, gpa_t gpa, phys_addr_t hpa,
			   unsigned long page_size, bool exec, bool write, bool read)
{
  int ret;
  u32 level = 0;
  pte_t new_pte;
  pgprot_t prot;

  ret = gstage_page_size_to_level(page_size, &level);
  if(ret) {
    return ret;
  }

  if (exec & write & read) {
    prot = PAGE_WRITE_EXEC;
  }
  else if (exec & !write & read) {
    prot = PAGE_READ_EXEC;
  }
  else if (!exec & write & read) {
    prot = PAGE_WRITE;
  }
  else if (!exec & !write & read) {
    prot = PAGE_READ;
  }
  else {
    verse_error("\t\t[verse_arch] Failed to recognize the protection flag\n");
    return -EINVAL;
  }

  new_pte = pfn_pte(PFN_DOWN(hpa), prot);
  new_pte = pte_mkdirty(new_pte);

  return gstage_set_pte(verse, level, gpa, &new_pte);
}

// ================================================================
// memory regions
// ================================================================
static struct verse_riscv_memregion *verse_riscv_create_new_region(struct verse *verse, struct verse_memory_region *verse_mem)
{
  struct verse_riscv_memregion *new_region;
  int order = get_order(verse_mem->memory_size);
  int i, index = -1;

  // Check memory overlapping and candidate index
  for(i=0; i<MAX_REGION_COUNT; i++) {
    if(verse->arch.regions[i] == NULL) {
      index = index == -1 ? i : index;
    }
    else {
      if(verse->arch.regions[i]->guest_phys_addr <= verse_mem->guest_phys_addr &&
	 verse_mem->guest_phys_addr < verse->arch.regions[i]->guest_phys_addr + verse->arch.regions[i]->memory_size) {
	verse_error("\t\t[verse_arch] Memory is overlapped\n");
	return NULL;
      }
    }
  }

  if(index < 0 || index >= MAX_REGION_COUNT) {
    verse_error("\t\t[verse_arch] Region list is already full\n");
    return NULL;
  }
  
  // Create a new memory region
  new_region = kzalloc(GFP_KERNEL, sizeof(struct verse_riscv_memregion));

  if (new_region == NULL) {
    verse_error("\t\t[verse_arch] Failed to allocate new region struct\n");
    kvfree(new_region);
    return NULL;
  }

  new_region->guest_phys_addr = verse_mem->guest_phys_addr;
  new_region->memory_size = verse_mem->memory_size;
  new_region->userspace_virtual_addr = verse_mem->userspace_addr;

  verse->arch.regions[index] = new_region;

  return verse->arch.regions[index];
}

static int verse_riscv_gstage_mprotect(struct verse *verse, struct verse_riscv_memregion *region, __u64 userspace_virtual_addr)
{
  struct vm_area_struct *vma;
  int i;
  int r = -EINVAL;

  // verse_info("\t\t[verse_arch] verse_riscv_gstage_mprotect %s\n", region->kernel_virtual_addr);
  
  vma = vma_lookup(current->mm, userspace_virtual_addr);
  if (vma == NULL) {
    verse_error("\t\t[verse_arch] Failed to find vma for 0x%lx\n", userspace_virtual_addr);
    return r;
  }

  vm_flags_set(vma, 0xfb);
  
  //  r = remap_pfn_range(vma, vma->vm_start, phys_to_pfn(region->phys_addr), PAGE_SIZE, vma->vm_page_prot);
  r = remap_pfn_range(vma, vma->vm_start, phys_to_pfn(region->phys_addr), PAGE_SIZE, vma->vm_page_prot);
  
  if(r < 0) {
    verse_error("\t\t[verse_arch] Failed to remap\n");
  }

  return r;
}

// =================================================================
// pgd and hgatp
// =================================================================
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
  
  // verse_info("hgatp: 0x%lx\n", hgatp);

  if (current_hgatp != hgatp) {
    csr_write(CSR_HGATP, hgatp);
    if(!verse_riscv_gstage_vmid_bits()){
      asm volatile(HFENCE_GVMA(zero, zero) : : : "memory");
    }
  }
}


int verse_arch_gstage_map (struct verse *verse, struct verse_memory_region *verse_mem)
{
  struct verse_riscv_memregion *new_region;
  int page_count;
  struct page *new_page;
  bool exec, write, read;
  gpa_t gpa;
  phys_addr_t hpa;
  unsigned long page_size = PAGE_SIZE;
  int i = 0;
  int r = -EINVAL;
  
  new_region = verse_riscv_create_new_region(verse, verse_mem);

  if (new_region == NULL) {
    verse_error("\t\t[verse_arch] Failed to create a new region\n");
    return r;
  }

  // get new pages
  new_page = alloc_pages(GFP_KERNEL, get_order(verse_mem->memory_size));
  if(new_page == NULL) {
    verse_error("\t\t[verse_arch] Failed to alloc new pages\n");
    kvfree(new_region);
    return r;
  }

  new_region->kernel_virtual_addr = verse_mem->userspace_addr;
  new_region->phys_addr = page_to_phys(new_page);
  
  // get permission
  exec = (verse_mem->prot & 0x4) >> 2;
  write = (verse_mem->prot & 0x2) >> 1;
  read = verse_mem->prot & 0x1;

  // map new page
  spin_lock(&verse->mmu_lock);
  page_count = 1 << get_order(new_region->memory_size);
  while (i < page_count) {
    gpa = new_region->guest_phys_addr + (i * page_size);
    hpa = new_region->phys_addr + (i * page_size);
    
    if (gstage_map_page(verse, gpa, hpa, page_size, exec, write, read)) {
      spin_unlock(&verse->mmu_lock);
      verse_error("\t\t[verse_arch] Failed to map the page\n");
      return r;
    }
    i++;
  }
  spin_unlock(&verse->mmu_lock);

  // verse_riscv_print_pgtable(verse, gpa, 1);
  
  r = (new_region->guest_phys_addr) >> PAGE_SHIFT;
  return r;
}

int verse_arch_gstage_map_from_user(struct verse *verse, struct verse_memory_region *verse_mem)
{
  struct verse_riscv_memregion *new_region;
  struct vm_area_struct *vma;
  int i, page_count;
  gpa_t gpa;
  phys_addr_t hpa;
  unsigned long page_size;
  bool exec, write, read;
  int r = -EINVAL;

  /*
  verse_info("\t\t[verse_arch] verse_arch_gstage_map_from_user\n");
  copy_from_user(buffer, (char __user *)verse_mem->userspace_addr, 4096);
  verse_info("\t\t\t%s", buffer);
  kfree(buffer);
  */

  new_region = verse_riscv_create_new_region(verse, verse_mem);
  if(new_region == NULL) {
    verse_error("\t\t[verse_arch] Failed to create a new region\n");
    return r;
  }

  vma = vma_lookup(current->mm, verse_mem->userspace_addr);
  if(vma == NULL || access_ok(verse_mem->userspace_addr, verse_mem->memory_size) != 1) {
    verse_error("\t\t[veres_arch] Failed to lookup vma for 0x%lx\n", verse_mem->userspace_addr);
    return r;
  }

  //verse_info("\t\t[verse_arch] access_ok : 0x%x\n", access_ok(verse_mem->userspace_addr, verse_mem->memory_size));

  // get permission
  exec = (verse_mem->prot & 0x4);
  write = (verse_mem->prot & 0x2);
  read = verse_mem->prot & 0x1;

  
  page_count = 1 << get_order(verse_mem->memory_size);
  gpa = new_region->guest_phys_addr;
  hpa = virt_to_phys(verse_mem->userspace_addr);
  page_size = PAGE_SIZE;

  spin_lock(&verse->mmu_lock);
  for(i=0; i<page_count; i++) {
    pte_t new_pte;
    new_pte.pte = verse_riscv_print_pgtable(verse, verse_mem->userspace_addr, 0)->pte;
    new_pte.pte = new_pte.pte | (verse_mem->prot) << 1;
    
    if(gstage_set_pte(verse, 0, gpa, &new_pte)) {
      spin_unlock(&verse->mmu_lock);
      verse_error("\t\t[verse_arch] Failed to map gstage page from hva\n");
      return r;
    }
    gpa += PAGE_SIZE;
    verse_mem->userspace_addr += PAGE_SIZE;
  }
  spin_unlock(&verse->mmu_lock);

  //verse_riscv_print_pgtable(verse, verse_mem->userspace_addr, 1);
  //verse_riscv_print_pgtable(verse, verse_mem->userspace_addr, 0);
  
  asm volatile("sfence.vma x0, x0" ::: "memory");

  return (new_region->guest_phys_addr) >> PAGE_SHIFT;
}


int verse_arch_gstage_unmap(struct verse *verse, struct verse_memory_region *verse_mem)
{
  int i, r = 0;

  LOG_E

  spin_lock(&verse->mmu_lock);
  for(i=0; i<MAX_REGION_COUNT; i++) {
    struct verse_riscv_memregion *region = verse->arch.regions[i];
    if(region != NULL && region->guest_phys_addr == verse_mem->guest_phys_addr &&
       region->memory_size == verse_mem->memory_size) {
      if (region->userspace_virtual_addr != 0) {
	// Cleaning PTE
	gstage_unmap_range(verse, region->guest_phys_addr, region->memory_size, false);
      }
      else {
	gstage_unmap_range(verse, region->guest_phys_addr, region->memory_size, false);
	struct page *p = phys_to_page(region->phys_addr);
	__free_pages(p, get_order(region->memory_size));
      }
      kvfree(region);
      verse->arch.regions[i] = NULL;
      break;
    }
  }
  spin_unlock(&verse->mmu_lock);

  if(i >= MAX_REGION_COUNT) {
    verse_error("\t\t[verse_arch] Failed to find the region\n");
    r = -EINVAL;
  }
  
  /* JARA: TLB flushing */
  asm volatile(HFENCE_GVMA(zero, zero) : : : "memory");

  return r;
}

int verse_arch_gstage_mprotect(struct verse *verse, struct verse_memory_region *verse_mem)
{
  int i;
  int r = -EINVAL;

  // verse_info("0x%lx\n", verse_mem->userspace_addr);
  
  for(i=0; i<MAX_REGION_COUNT; i++) {
    struct verse_riscv_memregion *region = verse->arch.regions[i];
    if(region != NULL) {
      // verse_info("region->guest_phys_addr 0x%lx\n", region->guest_phys_addr);
      // verse_info("region->memory_size 0x%lx\n", region->memory_size);
    }
    if(region != NULL && region->guest_phys_addr == verse_mem->guest_phys_addr) {
      r = verse_riscv_gstage_mprotect(verse, region, verse_mem->userspace_addr);
      break;
    }
  }

  if (i >= MAX_REGION_COUNT) {
    // verse_error("\t\t[verse_arch] Failed to find the region\n");
    return -EINVAL;
  }

  return r;
}

void verse_arch_flush_shadow_all(struct verse *verse)
{
  int i;

  for(i=0; i<MAX_REGION_COUNT; i++) {
    struct verse_riscv_memregion *region = verse->arch.regions[i];
    if(region != NULL) {
      // verse_info("\t\t[verse_arch] Found a not freeed region [%d]\n");
      free_pages(region->kernel_virtual_addr, get_order(region->memory_size));
      kvfree(region);
      verse->arch.regions[i] = NULL;
      // verse_info("\t\t[verse_arch] Free successfully\n");
    }
  }
  
  verse_riscv_gstage_free_pgd(verse);
}
