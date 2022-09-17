# SPDX-License-Identifier: GPL-2.0
# Makefile for KVM support for LOONGISA
#

OBJECT_FILES_NON_STANDARD_entry.o	:= y

common-objs-y = $(addprefix ../../../virt/kvm/, kvm_main.o coalesced_mmio.o \
				irqchip.o eventfd.o)

KVM := ../../../virt/kvm
common-objs-$(CONFIG_KVM_VFIO) += $(KVM)/vfio.o

EXTRA_CFLAGS += -Ivirt/kvm -Iarch/loongarch/kvm

kvm-objs := $(common-objs-y) loongisa.o emulate.o interrupt.o
kvm-objs += hypcall.o
kvm-objs += mmu.o

kvm-objs		+= cpu.o ls7a_irq.o ls3a_ipi.o irqchip-debug.o\
				timer.o ls3a_ext_irq.o ls7a_irqfd.o csr.o
obj-$(CONFIG_KVM)	+= kvm.o
obj-y			+= tlb.o entry.o fpu.o
