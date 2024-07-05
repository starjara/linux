# SPDX-License-Identifier: GPL-2.0
#
# Makefile for RISC-V VERSE support
#

ccflags-y += -I $(srctree)/$(src)

include $(srctree)/virt/verse/Makefile.verse

obj-$(CONFIG_VERSE) += verse.o

verse-y += main.o
verse-y += vm.o
verse-y += vmid.o
verse-y += mmu.o

