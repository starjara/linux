
#ifndef __LINUX_MINI_RISCV_H
#define __LINUX_MINI_RISCV_H

#ifndef __ASSEMBLY__

#include <linux/types.h>
#include <asm/bitsperlong.h>
#include <asm/ptrace.h>

#define __MINI_HAVE_READONLY_MEM

/*
 * ISA extension IDs specific to MINI. This is not the same as the host ISA
 * extension IDs as that is internal to the host and should not be exposed
 * to the guest. This should always be contiguous to keep the mapping simple
 * in MINI implementation.
 */
enum MINI_RISCV_ISA_EXT_ID {
	MINI_RISCV_ISA_EXT_A = 0,
	MINI_RISCV_ISA_EXT_C,
	MINI_RISCV_ISA_EXT_D,
	MINI_RISCV_ISA_EXT_F,
	MINI_RISCV_ISA_EXT_H,
	MINI_RISCV_ISA_EXT_I,
	MINI_RISCV_ISA_EXT_M,
	MINI_RISCV_ISA_EXT_SVPBMT,
	MINI_RISCV_ISA_EXT_SSTC,
	MINI_RISCV_ISA_EXT_SVINVAL,
	MINI_RISCV_ISA_EXT_ZIHINTPAUSE,
	MINI_RISCV_ISA_EXT_ZICBOM,
	MINI_RISCV_ISA_EXT_ZICBOZ,
	MINI_RISCV_ISA_EXT_ZBB,
	MINI_RISCV_ISA_EXT_SSAIA,
	MINI_RISCV_ISA_EXT_MAX,
};

/*
 * SBI extension IDs specific to MINI. This is not the same as the SBI
 * extension IDs defined by the RISC-V SBI specification.
 */
enum MINI_RISCV_SBI_EXT_ID {
	MINI_RISCV_SBI_EXT_V01 = 0,
	MINI_RISCV_SBI_EXT_TIME,
	MINI_RISCV_SBI_EXT_IPI,
	MINI_RISCV_SBI_EXT_RFENCE,
	MINI_RISCV_SBI_EXT_SRST,
	MINI_RISCV_SBI_EXT_HSM,
	MINI_RISCV_SBI_EXT_PMU,
	MINI_RISCV_SBI_EXT_EXPERIMENTAL,
	MINI_RISCV_SBI_EXT_VENDOR,
	MINI_RISCV_SBI_EXT_MAX,
};
