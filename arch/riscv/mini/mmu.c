#include <linux/mini_host.h>
#include <linux/kvm_host.h>
#include <linux/module.h>
#include <linux/hugetlb.h>

#include <asm/csr.h>
#include <asm/page.h>
#include <asm/pgtable.h>

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

    //mini_info("[mini] gstage_level_to_page_order\n");

	*out_pgorder = 12 + (level * gstage_index_bits);
	return 0;
}

static int gstage_level_to_page_size(u32 level, unsigned long *out_pgsize)
{
	int rc;
	unsigned long page_order = PAGE_SHIFT;

    //mini_info("[mini] gstage_level_to_page_size\n");

	rc = gstage_level_to_page_order(level, &page_order);
	if (rc)
		return rc;

	*out_pgsize = BIT(page_order);
	return 0;
}

static bool gstage_get_leaf_entry(struct mini *mini, gpa_t addr,
				  pte_t **ptepp, u32 *ptep_level)
{
	pte_t *ptep;
	u32 current_level = gstage_pgd_levels - 1;

	*ptep_level = current_level;
	ptep = (pte_t *)mini->arch.pgd;
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

static void gstage_remote_tlb_flush(struct mini *mini, u32 level, gpa_t addr)
{
	unsigned long order = PAGE_SHIFT;

	if (gstage_level_to_page_order(level, &order))
		return;
	addr &= ~(BIT(order) - 1);

	mini_riscv_hfence_gvma_vmid_gpa(mini, -1UL, 0, addr, BIT(order), order);
}

static int gstage_set_pte(struct mini *mini, u32 level,
			   struct kvm_mmu_memory_cache *pcache,
			   gpa_t addr, const pte_t *new_pte)
{
  u32 current_level = gstage_pgd_levels - 1;
  pte_t *next_ptep = (pte_t *)mini->arch.pgd;
  pte_t *ptep = &next_ptep[gstage_pte_index(addr, current_level)];

  /* mini_info("[mini] gstage_set_pte\n"); */
  /* mini_info("\t[mini] level: 0x%x\n", level); */
  /* mini_info("\t[mini] addr : 0x%llx\n", addr); */
  /* mini_info("\t[mini] pgd : 0x%llx\n", next_ptep); */
  /* mini_info("\t[mini] ptep : 0x%lx : 0x%016lx\n", ptep, pte_val(*ptep)); */
  /* mini_info("\t[mini] new_pte : 0x%lx : 0x%016lx\n", new_pte, pte_val(*new_pte)); */

  if (current_level < level)
    return -EINVAL;

  while (current_level != level) {
    /* mini_info("\t\t[mini] level : %d\n", current_level); */
    /* mini_info("\t\t[mini] next ptep : 0x%lx \n", next_ptep); */
    /* mini_info("\t\t[mini] index : %d\n", gstage_pte_index(addr, current_level)); */
    /* mini_info("\t\t\t[mini] before ptep : 0x%lx : 0x%lx\n", ptep, ptep->pte); */
    if (gstage_pte_leaf(ptep))
      return -EEXIST;

    if (!pte_val(*ptep)) {
      if (!pcache)
	return -ENOMEM;
      next_ptep = mini_mmu_memory_cache_alloc(pcache);
      if (!next_ptep)
	return -ENOMEM;
      *ptep = pfn_pte(PFN_DOWN(__pa(next_ptep)),
		      __pgprot(_PAGE_TABLE));
    } else {
      if (gstage_pte_leaf(ptep))
	return -EEXIST;
      next_ptep = (pte_t *)gstage_pte_page_vaddr(*ptep);
    }

    /* mini_info("\t\t\t[mini] after ptep : 0x%lx : 0x%lx\n", ptep, ptep->pte); */
    
    current_level--;
    ptep = &next_ptep[gstage_pte_index(addr, current_level)];
  }

  *ptep = *new_pte;
  if (gstage_pte_leaf(ptep))
    gstage_remote_tlb_flush(mini, current_level, addr);

  /* mini_info("\t[mini] level : %d\n", current_level); */
  /* mini_info("\t[mini] next ptep : 0x%lx \n", next_ptep); */
  /* mini_info("\t[mini] index : %d\n", gstage_pte_index(addr, current_level)); */
  /* mini_info("\t[mini] ptep : 0x%lx : 0x%lx\n", ptep, pte_val(*ptep)); */
  /* mini_info("\t[mini] new_pte : 0x%lx : 0x%lx\n", new_pte, pte_val(*new_pte)); */

  return 0;
}

static int gstage_map_page(struct mini *mini,
			   struct kvm_mmu_memory_cache *pcache,
			   gpa_t gpa, phys_addr_t hpa,
			   unsigned long page_size,
			   bool page_rdonly, bool page_exec)
{
  int ret;
  u32 level = 0;
  pte_t new_pte;
  pgprot_t prot;

  /* mini_info("[mini] gstage_map_page\n"); */
  /* mini_info("\t[gstage_map_page] gpa : 0x%lx, hpa : 0x%lx\n", gpa, hpa); */

  ret = gstage_page_size_to_level(page_size, &level);
  /* mini_info("\t[gstage_map_page] ret : %d page_size: %d, level: %d\n", ret, page_size, level); */
  if (ret)
    return ret;

  /*
   * A RISC-V implementation can choose to either:
   * 1) Update 'A' and 'D' PTE bits in hardware
   * 2) Generate page fault when 'A' and/or 'D' bits are not set
   *    PTE so that software can update these bits.
   *
   * We support both options mentioned above. To achieve this, we
   * always set 'A' and 'D' PTE bits at time of creating G-stage
   * mapping. To support MINI dirty page logging with both options
   * mentioned above, we will write-protect G-stage PTEs to track
   * dirty pages.
   */

  if (page_exec) {
    if (page_rdonly)
      prot = PAGE_READ_EXEC;
    else
      prot = PAGE_WRITE_EXEC;
  } else {
    if (page_rdonly)
      prot = PAGE_READ;
    else
      prot = PAGE_WRITE;
  }
  new_pte = pfn_pte(PFN_DOWN(hpa), prot);
  new_pte = pte_mkdirty(new_pte);

  return gstage_set_pte(mini, level, pcache, gpa, &new_pte);
}

enum gstage_op {
	GSTAGE_OP_NOP = 0,	/* Nothing */
	GSTAGE_OP_CLEAR,	/* Clear/Unmap */
	GSTAGE_OP_WP,		/* Write-protect */
};

static void gstage_op_pte(struct mini *mini, gpa_t addr,
			  pte_t *ptep, u32 ptep_level, enum gstage_op op)
{
	int i, ret;
	pte_t *next_ptep;
	u32 next_ptep_level;
	unsigned long next_page_size, page_size;
    
   //mini_info("[mini] gstage_op_pte %d\n", op);

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

		if (op == GSTAGE_OP_CLEAR) {
			set_pte(ptep, __pte(0));
            //mini_info("\tclear1\n");
        }
		for (i = 0; i < PTRS_PER_PTE; i++)
			gstage_op_pte(mini, addr + i * next_page_size,
					&next_ptep[i], next_ptep_level, op);
		if (op == GSTAGE_OP_CLEAR)
			put_page(virt_to_page(next_ptep));
	} else {
		if (op == GSTAGE_OP_CLEAR) {
            //mini_info("\tbefore-pte_p : %x\n", *ptep);
			set_pte(ptep, __pte(0));
            //mini_info("\tafter-pte_p : %x\n", *ptep);
        }
		else if (op == GSTAGE_OP_WP)
			set_pte(ptep, __pte(pte_val(*ptep) & ~_PAGE_WRITE));
		gstage_remote_tlb_flush(mini, ptep_level, addr);
	}
}

static void gstage_unmap_range(struct mini *mini, gpa_t start,
			       gpa_t size, bool may_block)
{
	int ret;
	pte_t *ptep;
	u32 ptep_level;
	bool found_leaf;
	unsigned long page_size;
	gpa_t addr = start, end = start + size;

	//    mini_info("[mini] gstage_unmap_range\n");
	//    mini_info("start : 0x%x, end : 0x%x\n", start, end);

	while (addr < end) {
		found_leaf = gstage_get_leaf_entry(mini, addr,
						   &ptep, &ptep_level);
		ret = gstage_level_to_page_size(ptep_level, &page_size);

		//        mini_info("\t[mini] level: %d, size : %d, addr : 0x%x, leaf : %d\n", ptep_level, page_size, addr, found_leaf);
        
		if (ret)
			break;

		if (!found_leaf)
			goto next;

		if (!(addr & (page_size - 1)) && ((end - addr) >= page_size))
			gstage_op_pte(mini, addr, ptep,
				      ptep_level, GSTAGE_OP_CLEAR);

next:
		addr += page_size;

		/*
		 * If the range is too large, release the mini->mmu_lock
		 * to prevent starvation and lockup detector warnings.
		 */
		if (may_block && addr < end)
			cond_resched_lock(&mini->mmu_lock);
	}
}

static void gstage_wp_range(struct mini *mini, gpa_t start, gpa_t end)
{
	int ret;
	pte_t *ptep;
	u32 ptep_level;
	bool found_leaf;
	gpa_t addr = start;
	unsigned long page_size;

    mini_info("[mini] gstage_wp_range\n");
	while (addr < end) {
		found_leaf = gstage_get_leaf_entry(mini, addr,
						   &ptep, &ptep_level);
		ret = gstage_level_to_page_size(ptep_level, &page_size);
		if (ret)
			break;

		if (!found_leaf)
			goto next;

		if (!(addr & (page_size - 1)) && ((end - addr) >= page_size))
			gstage_op_pte(mini, addr, ptep,
				      ptep_level, GSTAGE_OP_WP);

next:
		addr += page_size;
	}
}

static void gstage_wp_memory_region(struct mini *mini, int slot)
{
	struct kvm_memslots *slots = mini_memslots(mini);
	struct kvm_memory_slot *memslot = mini_id_to_memslot(slots, slot);
	phys_addr_t start = memslot->base_gfn << PAGE_SHIFT;
	phys_addr_t end = (memslot->base_gfn + memslot->npages) << PAGE_SHIFT;

    mini_info("[mini] gstage_wp_memory_region\n");
	spin_lock(&mini->mmu_lock);
	gstage_wp_range(mini, start, end);
	spin_unlock(&mini->mmu_lock);
	mini_flush_remote_tlbs(mini);
}

int mini_riscv_gstage_ioremap(struct mini *mini, gpa_t gpa,
			     phys_addr_t hpa, unsigned long size,
			     bool writable, bool in_atomic)
{
	pte_t pte;
	int ret = 0;
	unsigned long pfn;
	phys_addr_t addr, end;
	struct kvm_mmu_memory_cache pcache = {
		.gfp_custom = (in_atomic) ? GFP_ATOMIC | __GFP_ACCOUNT : 0,
		.gfp_zero = __GFP_ZERO,
	};

    mini_info("[mini] mini_riscv_gstage_ioremap\n");

	end = (gpa + size + PAGE_SIZE - 1) & PAGE_MASK;
	pfn = __phys_to_pfn(hpa);

	for (addr = gpa; addr < end; addr += PAGE_SIZE) {
		pte = pfn_pte(pfn, PAGE_KERNEL_IO);

		if (!writable)
			pte = pte_wrprotect(pte);

		ret = kvm_mmu_topup_memory_cache(&pcache, gstage_pgd_levels);
		if (ret)
			goto out;

		spin_lock(&mini->mmu_lock);
		ret = gstage_set_pte(mini, 0, &pcache, addr, &pte);
		spin_unlock(&mini->mmu_lock);
		if (ret)
			goto out;

		pfn++;
	}

out:
	kvm_mmu_free_memory_cache(&pcache);
	return ret;
}

void mini_riscv_gstage_iounmap(struct mini *mini, gpa_t gpa, unsigned long size)
{
	spin_lock(&mini->mmu_lock);
	gstage_unmap_range(mini, gpa, size, false);
	spin_unlock(&mini->mmu_lock);
}

void mini_arch_free_memslot(struct mini *mini, struct kvm_memory_slot *free)
{
}

void mini_arch_memslots_updated(struct mini *mini, u64 gen)
{
}

void mini_arch_flush_shadow_all(struct mini *mini)
{
	mini_riscv_gstage_free_pgd(mini);
}

void mini_arch_flush_remote_tlbs_memslot(struct mini *mini,
					const struct kvm_memory_slot *memslot)
{
	mini_flush_remote_tlbs(mini);
}

void mini_arch_flush_shadow_memslot(struct mini *mini,
				   struct kvm_memory_slot *slot)
{
	gpa_t gpa = slot->base_gfn << PAGE_SHIFT;
	phys_addr_t size = slot->npages << PAGE_SHIFT;

	spin_lock(&mini->mmu_lock);
	gstage_unmap_range(mini, gpa, size, false);
	spin_unlock(&mini->mmu_lock);
}

void mini_arch_commit_memory_region(struct mini *mini,
				struct kvm_memory_slot *old,
				const struct kvm_memory_slot *new,
				enum kvm_mr_change change)
{
    mini_info("[mini] mini_arch_commit_memory_region\n");
	/*
	 * At this point memslot has been committed and there is an
	 * allocated dirty_bitmap[], dirty pages will be tracked while
	 * the memory slot is write protected.
	 */
	if (change != KVM_MR_DELETE && new->flags & KVM_MEM_LOG_DIRTY_PAGES)
		gstage_wp_memory_region(mini, new->id);
}

int mini_arch_prepare_memory_region(struct mini *mini,
				const struct kvm_memory_slot *old,
				struct kvm_memory_slot *new,
				enum kvm_mr_change change)
{
	hva_t hva, reg_end, size;
	gpa_t base_gpa;
	bool writable;
	int ret = 0;

    mini_info("[mini] mini_arch_prepare_memory_region\n");

	if (change != KVM_MR_CREATE && change != KVM_MR_MOVE &&
			change != KVM_MR_FLAGS_ONLY)
		return 0;

	/*
	 * Prevent userspace from creating a memory region outside of the GPA
	 * space addressable by the MINI guest GPA space.
	 */
	mini_info("New: 0x%016lx, Base : 0x%016lx\n", (new->base_gfn + new->npages), (gstage_gpa_size >> PAGE_SHIFT));

	if ((new->base_gfn + new->npages) >=
	    (gstage_gpa_size >> PAGE_SHIFT))
		return -EFAULT;

	hva = new->userspace_addr;
	size = new->npages << PAGE_SHIFT;
	reg_end = hva + size;
	base_gpa = new->base_gfn << PAGE_SHIFT;
	writable = !(new->flags & MINI_MEM_READONLY);

    mini_info("\t[mini] hva : 0x%lx\n", hva);
    mini_info("\t[mini] size : 0x%lx\n", size);
    mini_info("\t[mini] base_gpa : 0x%lx\n", base_gpa);

	mmap_read_lock(current->mm);

	/*
	 * A memory region could potentially cover multiple VMAs, and
	 * any holes between them, so iterate over all of them to find
	 * out if we can map any of them right now.
	 *
	 *     +--------------------------------------------+
	 * +---------------+----------------+   +----------------+
	 * |   : VMA 1     |      VMA 2     |   |    VMA 3  :    |
	 * +---------------+----------------+   +----------------+
	 *     |               memory region                |
	 *     +--------------------------------------------+
	 */
	do {
		struct vm_area_struct *vma = find_vma(current->mm, hva);
		hva_t vm_start, vm_end;

		if (!vma || vma->vm_start >= reg_end)
			break;

		/*
		 * Mapping a read-only VMA is only allowed if the
		 * memory region is configured as read-only.
		 */

        /*
		if (writable && !(vma->vm_flags & VM_WRITE)) {
			ret = -EPERM;
			break;
		}
        */

		/* Take the intersection of this VMA with the memory region */
		vm_start = max(hva, vma->vm_start);
		vm_end = min(reg_end, vma->vm_end);
        mini_info("vm_start : 0x%lx\n", vm_start);
        mini_info("vm_end : 0x%lx\n", vm_end);

		if (vma->vm_flags & VM_PFNMAP) {
			gpa_t gpa = base_gpa + (vm_start - hva);
			phys_addr_t pa;

			pa = (phys_addr_t)vma->vm_pgoff << PAGE_SHIFT;
			pa += vm_start - vma->vm_start;

			/* IO region dirty page logging not allowed */
			if (new->flags & MINI_MEM_LOG_DIRTY_PAGES) {
				ret = -EINVAL;
				goto out;
			}

			ret = mini_riscv_gstage_ioremap(mini, gpa, pa,
						       vm_end - vm_start,
						       writable, false);
			if (ret)
				break;
		}
		hva = vm_end;
	} while (hva < reg_end);

	if (change == KVM_MR_FLAGS_ONLY)
		goto out;

	if (ret)
		mini_riscv_gstage_iounmap(mini, base_gpa, size);

out:
	mmap_read_unlock(current->mm);
	return ret;
}

/*
bool mini_unmap_gfn_range(struct mini *mini, struct mini_gfn_range *range)
{
	if (!kvm->arch.pgd)
		return false;

	gstage_unmap_range(kvm, range->start << PAGE_SHIFT,
			   (range->end - range->start) << PAGE_SHIFT,
			   range->may_block);
	return false;
}
*/

int mini_riscv_gstage_alloc_pgd(struct mini *mini)
{
  struct page *pgd_page;

  mini_info("mini_riscv_gstage_alloc_pgd\n");

  if (mini->arch.pgd != NULL) {
    mini_err("mini_arch already initialized?\n");
    return -EINVAL;
  }

  pgd_page = alloc_pages(GFP_KERNEL | __GFP_ZERO,
			 get_order(gstage_pgd_size));
  if (!pgd_page)
    return -ENOMEM;
  mini->arch.pgd = page_to_virt(pgd_page);
  mini->arch.pgd_phys = page_to_phys(pgd_page);

  mini_info("\t[mini_riscv_gstage_alloc_pgd] pgd_page : 0x%lx\n", pgd_page);
  mini_info("\t[mini_riscv_gstage_alloc_pgd] pgd_virt : 0x%lx\n", mini->arch.pgd);
  mini_info("\t[mini_riscv_gstage_alloc_pgd] pgd_phys : 0x%lx\n", mini->arch.pgd_phys);
    
  mini_info("\t[mini_riscv_gstage_alloc_pgd] pgd_page : 0x%lx\n", *pgd_page);
  mini_info("\t[mini_riscv_gstage_alloc_pgd] pgd_virt : 0x%lx\n", *mini->arch.pgd);

  return 0;
}

void mini_riscv_gstage_free_pgd(struct mini *mini)
{
  void *pgd = NULL;
  
  spin_lock(&mini->mmu_lock);

  if (mini->arch.pgd) {
    gstage_unmap_range(mini, 0UL, gstage_gpa_size, false);
    pgd = READ_ONCE(mini->arch.pgd);
    mini->arch.pgd = NULL;
    mini->arch.pgd_phys = 0;
  }
  spin_unlock(&mini->mmu_lock);

  pgd = mini->arch.pgd;
  
  if (pgd)
    free_pages((unsigned long)pgd, get_order(gstage_pgd_size));
}

void mini_riscv_gstage_update_hgatp(struct mini *mini)
{
  unsigned long hgatp = gstage_mode;
  struct mini_arch *k = &(mini->arch);
  unsigned long current_hgatp = csr_read(CSR_HGATP);

  mini_info("mini_riscv_gstage_update_hgatp\n");
  mini_info("current_hgatp : 0x%lx\n", current_hgatp);

  hgatp |= (READ_ONCE(k->vmid.vmid) << HGATP_VMID_SHIFT) & HGATP_VMID;
  hgatp |= (k->pgd_phys >> PAGE_SHIFT) & HGATP_PPN;

  mini_info("hgatp : 0x%lx\n", hgatp);

  if (current_hgatp != hgatp) {
    csr_write(CSR_HGATP, hgatp);

    if (!mini_riscv_gstage_vmid_bits())
      asm volatile(HFENCE_GVMA(zero, zero) : : : "memory");
  }
}

/*
int mini_riscv_gstage_map(struct mini_vcpu *vcpu,
			 struct kvm_memory_slot *memslot,
			 gpa_t gpa, unsigned long hva, bool is_write)
             */
int mini_riscv_gstage_map(struct mini *mini,
			 struct kvm_memory_slot *memslot,
			 gpa_t gpa, unsigned long hva, bool is_write)
{
  int ret;
  kvm_pfn_t hfn;
  bool writable;
  short vma_pageshift;
  gfn_t gfn = gpa >> PAGE_SHIFT;
  struct vm_area_struct *vma;
  //struct mini *mini = vcpu->mini;
  //struct kvm_mmu_memory_cache *pcache = &vcpu->arch.mmu_page_cache;
  struct kvm_mmu_memory_cache *pcache = &mini->mmu_page_cache;
  bool logging = (memslot->dirty_bitmap &&
		  !(memslot->flags & MINI_MEM_READONLY)) ? true : false;
  unsigned long vma_pagesize, mmu_seq;

  /* mini_info("[mini] mini_riscv_gstage_map\n"); */
  /* mini_info("[mini] gpa : 0x%lx, hva : 0x%lx\n", gpa, hva); */

  /* We need minimum second+third level pages */
  ret = kvm_mmu_topup_memory_cache(pcache, gstage_pgd_levels);
  if (ret) {
    mini_err("Failed to topup G-stage cache\n");
    return ret;
  }

  unsigned long phys_addr = virt_to_phys(hva);
  /* mini_info("[mini] hpa : 0x%lx\n", phys_addr); */


  /**********************************

	mmap_read_lock(current->mm);
	//mini_info("[mini] curren->mm->next : 0x%x prev : 0x%x\n", current->mm->next);

	vma = vma_lookup(current->mm, hva);
    
	//vma = vma_lookup(p->mm, hva);
	//vma = vma_lookup(current->active_mm, hva);
    
	if (unlikely(!vma)) {
		mini_err("Failed to find VMA for hva 0x%lx\n", hva);
		mmap_read_unlock(current->mm);
		//mmap_read_unlock(p->mm);
		return -EFAULT;
	}

    mini_info("Set VMA\n");

	if (is_vm_hugetlb_page(vma))
		vma_pageshift = huge_page_shift(hstate_vma(vma));
	else
		vma_pageshift = PAGE_SHIFT;

    mini_info("Get vma_pagesize\n");

	vma_pagesize = 1ULL << vma_pageshift;
	if (logging || (vma->vm_flags & VM_PFNMAP))
		vma_pagesize = PAGE_SIZE;

	if (vma_pagesize == PMD_SIZE || vma_pagesize == PUD_SIZE)
		gfn = (gpa & huge_page_mask(hstate_vma(vma))) >> PAGE_SHIFT;

    mini_info("Set vma_pagesize\n");

  ****************************/

  /*
   * Read mmu_invalidate_seq so that MINI can detect if the results of
   * vma_lookup() or gfn_to_pfn_prot() become stale priort to acquiring
   * mini->mmu_lock.
   *
   * Rely on mmap_read_unlock() for an implicit smp_rmb(), which pairs
   * with the smp_wmb() in mini_mmu_invalidate_end().
   */

  /**************************************
	mmu_seq = mini->mmu_invalidate_seq;
	mmap_read_unlock(current->mm);
	//mmap_read_unlock(p->mm);

	if (vma_pagesize != PUD_SIZE &&
	    vma_pagesize != PMD_SIZE &&
	    vma_pagesize != PAGE_SIZE) {
		mini_err("Invalid VMA page size 0x%lx\n", vma_pagesize);
		return -EFAULT;
	}
  ****************************************/

  vma_pagesize = PAGE_SIZE;

  //hfn = mini_gfn_to_pfn_prot(mini, gfn, is_write, &writable);
  //hfn = virt_to_pfn(hva);
  //if(hfn == KVM_PFN_NOSLOT) {
  if(phys_addr == KVM_PFN_NOSLOT) {
    mini_info("[mini] can't find hfn\n");
    return -EFAULT;
  }
  //if (hfn == KVM_PFN_ERR_HWPOISON) {
  if (phys_addr == KVM_PFN_ERR_HWPOISON) {
    send_sig_mceerr(BUS_MCEERR_AR, (void __user *)hva,
		    vma_pageshift, current);
    return 0;
  }

  //mini_info("\t[gstage_map] hfn : %lx\n", hfn);

  /*
    if (is_error_noslot_pfn(hfn))
    return -EFAULT;
    mini_info("\t[gstage_map] noslot\n");
  */

  /*
   * If logging is active then we allow writable pages only
   * for write faults.
   */
  if (logging && !is_write)
    writable = false;

  spin_lock(&mini->mmu_lock);

  if (mini_mmu_invalidate_retry(mini, mmu_seq))
    goto out_unlock;
  /* mini_info("\t[gstage_map] invalidate_retry\n"); */

  /*
    unsigned long pfn = virt_to_phys(hva >> PAGE_SHIFT);
    mini_info("\t[gstage_map] pfn : %lx\n", pfn);
  */

  if (writable) {
    //mini_info("\t[gstage_map] write_able\n");
    //mini_set_pfn_dirty(hfn);
    //mark_page_dirty(mini, gfn);
    /*
      ret = gstage_map_page(mini, pcache, gpa, hfn << PAGE_SHIFT,
      vma_pagesize, false, true);
    */
    ret = gstage_map_page(mini, pcache, gpa, phys_addr,
			  vma_pagesize, false, true);
  } else {
    //mini_info("\t[gstage_map] non-write_able\n");
    /*
      ret = gstage_map_page(mini, pcache, gpa, hfn << PAGE_SHIFT, //hfn
      vma_pagesize, true, true);
    */
    ret = gstage_map_page(mini, pcache, gpa, phys_addr,
			  vma_pagesize, false, true);
  }

  //mini_info("\t[mini] kmem_cache : %p\n", pcache->kmem_cache);
  //mini_info("\t[mini] size: %u\n", (pcache->kmem_cache)->size);

  if (ret)
    mini_err("Failed to map in G-stage\n");

  /*
    struct page *p = virt_to_page(hva);
    mini_info("ref count = %d\n", page_ref_count(p));
    page_ref_inc(p);
    mini_info("ref count = %d\n", page_ref_count(p));
  */


 out_unlock:
  spin_unlock(&mini->mmu_lock);
  //mini_set_pfn_accessed(hfn);
  //mini_release_pfn_clean(hfn);
  mini_set_pfn_accessed(phys_addr);
  mini_release_pfn_clean(phys_addr);

  return ret;
}
