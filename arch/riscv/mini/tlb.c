#include <linux/bitmap.h>
#include <linux/cpumask.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/smp.h>
#include <linux/mini_host.h>
#include <asm/cacheflush.h>
#include <asm/csr.h>
#include <asm/hwcap.h>
#include <asm/insn-def.h>

#define has_svinval()	riscv_has_extension_unlikely(RISCV_ISA_EXT_SVINVAL)

void mini_riscv_local_hfence_gvma_vmid_gpa(unsigned long vmid,
					  gpa_t gpa, gpa_t gpsz,
					  unsigned long order)
{
	gpa_t pos;

	if (PTRS_PER_PTE < (gpsz >> order)) {
		mini_riscv_local_hfence_gvma_vmid_all(vmid);
		return;
	}

	if (has_svinval()) {
		asm volatile (SFENCE_W_INVAL() ::: "memory");
		for (pos = gpa; pos < (gpa + gpsz); pos += BIT(order))
			asm volatile (HINVAL_GVMA(%0, %1)
			: : "r" (pos >> 2), "r" (vmid) : "memory");
		asm volatile (SFENCE_INVAL_IR() ::: "memory");
	} else {
		for (pos = gpa; pos < (gpa + gpsz); pos += BIT(order))
			asm volatile (HFENCE_GVMA(%0, %1)
			: : "r" (pos >> 2), "r" (vmid) : "memory");
	}
}

void mini_riscv_local_hfence_gvma_vmid_all(unsigned long vmid)
{
	asm volatile(HFENCE_GVMA(zero, %0) : : "r" (vmid) : "memory");
}

void mini_riscv_local_hfence_gvma_gpa(gpa_t gpa, gpa_t gpsz,
				     unsigned long order)
{
	gpa_t pos;

	if (PTRS_PER_PTE < (gpsz >> order)) {
		mini_riscv_local_hfence_gvma_all();
		return;
	}

	if (has_svinval()) {
		asm volatile (SFENCE_W_INVAL() ::: "memory");
		for (pos = gpa; pos < (gpa + gpsz); pos += BIT(order))
			asm volatile(HINVAL_GVMA(%0, zero)
			: : "r" (pos >> 2) : "memory");
		asm volatile (SFENCE_INVAL_IR() ::: "memory");
	} else {
		for (pos = gpa; pos < (gpa + gpsz); pos += BIT(order))
			asm volatile(HFENCE_GVMA(%0, zero)
			: : "r" (pos >> 2) : "memory");
	}
}

void mini_riscv_local_hfence_gvma_all(void)
{
	asm volatile(HFENCE_GVMA(zero, zero) : : : "memory");
}

static bool vcpu_hfence_enqueue(struct mini_vcpu *vcpu,
				const struct mini_riscv_hfence *data)
{
	bool ret = false;
	struct mini_vcpu_arch *varch = &vcpu->arch;

	spin_lock(&varch->hfence_lock);

	if (!varch->hfence_queue[varch->hfence_tail].type) {
		memcpy(&varch->hfence_queue[varch->hfence_tail],
		       data, sizeof(*data));

		varch->hfence_tail++;
		if (varch->hfence_tail == MINI_RISCV_VCPU_MAX_HFENCE)
			varch->hfence_tail = 0;

		ret = true;
	}

	spin_unlock(&varch->hfence_lock);

	return ret;
}

static void make_xfence_request(struct mini *mini,
				unsigned long hbase, unsigned long hmask,
				unsigned int req, unsigned int fallback_req,
				const struct mini_riscv_hfence *data)
{
	unsigned long i;
	struct mini_vcpu *vcpu;
	unsigned int actual_req = req;
	DECLARE_BITMAP(vcpu_mask, MINI_MAX_VCPUS);

	bitmap_clear(vcpu_mask, 0, MINI_MAX_VCPUS);
	mini_for_each_vcpu(i, vcpu, mini) {
		if (hbase != -1UL) {
			if (vcpu->vcpu_id < hbase)
				continue;
			if (!(hmask & (1UL << (vcpu->vcpu_id - hbase))))
				continue;
		}

		bitmap_set(vcpu_mask, i, 1);

		if (!data || !data->type)
			continue;

		/*
		 * Enqueue hfence data to VCPU hfence queue. If we don't
		 * have space in the VCPU hfence queue then fallback to
		 * a more conservative hfence request.
		 */
		if (!vcpu_hfence_enqueue(vcpu, data))
			actual_req = fallback_req;
	}

	mini_make_vcpus_request_mask(mini, actual_req, vcpu_mask);
}

void mini_riscv_hfence_gvma_vmid_gpa(struct mini *mini,
				    unsigned long hbase, unsigned long hmask,
				    gpa_t gpa, gpa_t gpsz,
				    unsigned long order)
{
	struct mini_riscv_hfence data;

	data.type = MINI_RISCV_HFENCE_GVMA_VMID_GPA;
	data.asid = 0;
	data.addr = gpa;
	data.size = gpsz;
	data.order = order;
	make_xfence_request(mini, hbase, hmask, MINI_REQ_HFENCE,
			    MINI_REQ_HFENCE_GVMA_VMID_ALL, &data);
}
