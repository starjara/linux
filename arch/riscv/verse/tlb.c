#include <linux/module.h>
#include <linux/verse_host.h>

/* static void make_xfence_request(struct verse *verse, */
/* 				unsigned long hbase, unsigned long hmask, */
/* 				unsigned int req, unsigned int fallback_req, */
/* 				const struct verse_riscv_hfence *data) */
/* { */
/*   unsigned long i; */
/*   struct verse_vcpu *vcpu; */
/*   unsigned int actual_req = req; */
/*   DECLARE_BITMAP(vcpu_mask, VERSE_MAX_VCPUS); */

/*   bitmap_clear(vcpu_mask, 0, VERSE_MAX_VCPUS); */
/*   verse_for_each_vcpu(i, vcpu, verse) { */
/*     if (hbase != -1UL) { */
/*       if (vcpu->vcpu_id < hbase) */
/* 	continue; */
/*       if (!(hmask & (1UL << (vcpu->vcpu_id - hbase)))) */
/* 	continue; */
/*     } */

/*     bitmap_set(vcpu_mask, i, 1); */

/*     if (!data || !data->type) */
/*       continue; */

/*     /\* */
/*      * Enqueue hfence data to VCPU hfence queue. If we don't */
/*      * have space in the VCPU hfence queue then fallback to */
/*      * a more conservative hfence request. */
/*      *\/ */
/*     if (!vcpu_hfence_enqueue(vcpu, data)) */
/*       actual_req = fallback_req; */
/*   } */

/*   verse_make_vcpus_request_mask(verse, actual_req, vcpu_mask); */
/* } */


/* void verse_riscv_hfence_gvma_vmid_gpa(struct verse *verse, */
/* 				    unsigned long hbase, unsigned long hmask, */
/* 				    gpa_t gpa, gpa_t gpsz, */
/* 				    unsigned long order) */
/* { */
/*   struct verse_riscv_hfence data; */

/*   data.type = VERSE_RISCV_HFENCE_GVMA_VMID_GPA; */
/*   data.asid = 0; */
/*   data.addr = gpa; */
/*   data.size = gpsz; */
/*   data.order = order; */
/*   make_xfence_request(verse, hbase, hmask, VERSE_REQ_HFENCE, */
/* 		      VERSE_REQ_HFENCE_GVMA_VMID_ALL, &data); */
/* } */
