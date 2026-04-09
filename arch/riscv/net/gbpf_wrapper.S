#include <linux/linkage.h>
#include <asm/asm.h>
#include "gbpf_offset.h"

SYM_FUNC_START(gbpf_call_dfunc)
	addi	sp, sp, -16
	REG_S	s11, 0(sp)
	REG_S	s10, 8(sp)

	/* a0 = gbpf_aux */
	/* a1 = ctx */
	/* a2 = insnsi */
	/* a3 = bpf_func */
	/* a4 = dfunc */

	mv	s11, a0

	/* old HGATP -> s10 */
	csrr	s10, hgatp

	/* save old HGATP into gbpf_aux->old_hgatp */
	/* offset 맞게 바꿔야 함 */
	REG_S	s10, GBPF_AUX_OLD_HGATP_OFF(s11)

	/* load new HGATP */
	REG_L	t0, GBPF_AUX_NEW_HGATP_OFF(s11)
	csrw	hgatp, t0

	/* call dfunc(ctx, insnsi, bpf_func) */
	mv	a0, a1
	mv	a1, a2
	mv	a2, a3
	jalr	a4

	/* restore old HGATP */
	REG_L	t0, GBPF_AUX_OLD_HGATP_OFF(s11)
	csrw	hgatp, t0

	REG_L	s11, 0(sp)
	REG_L	s10, 8(sp)
	addi	sp, sp, 16
	ret
SYM_FUNC_END(gbpf_call_dfunc)
EXPORT_SYMBOL_GPL(gbpf_call_dfunc)
