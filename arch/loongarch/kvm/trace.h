/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2020 Loongson  Technologies, Inc.  All rights reserved.
 * Authors: Xing Li <lixing@loongson.cn>
 */

#if !defined(_TRACE_KVM_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_KVM_H

#include <linux/tracepoint.h>
#include "kvm_csr.h"

#undef TRACE_SYSTEM
#define TRACE_SYSTEM kvm
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE trace

/*
 * arch/loongarch/kvm/loongisa.c
 */
extern bool kvm_trace_guest_mode_change;
int kvm_guest_mode_change_trace_reg(void);
void kvm_guest_mode_change_trace_unreg(void);

/*
 * Tracepoints for VM enters
 */
DECLARE_EVENT_CLASS(kvm_transition,
	TP_PROTO(struct kvm_vcpu *vcpu),
	TP_ARGS(vcpu),
	TP_STRUCT__entry(
		__field(unsigned long, pc)
	),

	TP_fast_assign(
		__entry->pc = vcpu->arch.pc;
	),

	TP_printk("PC: 0x%08lx",
		  __entry->pc)
);

DEFINE_EVENT(kvm_transition, kvm_enter,
	     TP_PROTO(struct kvm_vcpu *vcpu),
	     TP_ARGS(vcpu));

DEFINE_EVENT(kvm_transition, kvm_reenter,
	     TP_PROTO(struct kvm_vcpu *vcpu),
	     TP_ARGS(vcpu));

DEFINE_EVENT(kvm_transition, kvm_out,
	     TP_PROTO(struct kvm_vcpu *vcpu),
	     TP_ARGS(vcpu));

/* The first 32 exit reasons correspond to Cause.ExcCode */
#define KVM_TRACE_EXIT_INT		 0
#define KVM_TRACE_EXIT_TLBLD		 1
#define KVM_TRACE_EXIT_TLBST		 2
#define KVM_TRACE_EXIT_TLBI		 3
#define KVM_TRACE_EXIT_TLBMOD		 4
#define KVM_TRACE_EXIT_TLBRI		 5
#define KVM_TRACE_EXIT_TLBXI		 6
#define KVM_TRACE_EXIT_TLBPE		 7
#define KVM_TRACE_EXIT_ADDE		 8
#define KVM_TRACE_EXIT_UNALIGN		 9
#define KVM_TRACE_EXIT_ODB		10
#define KVM_TRACE_EXIT_SYSCALL		11
#define KVM_TRACE_EXIT_BP		12
#define KVM_TRACE_EXIT_RI		13
#define KVM_TRACE_EXIT_IPE		14
#define KVM_TRACE_EXIT_FPDIS		15
#define KVM_TRACE_EXIT_LSXDIS		16
#define KVM_TRACE_EXIT_LASXDIS		17
#define KVM_TRACE_EXIT_FPE		18
/* Further exit reasons */
#define KVM_TRACE_EXIT_WAIT		32
#define KVM_TRACE_EXIT_CACHE		33
#define KVM_TRACE_EXIT_SIGNAL		34
/* 32 exit reasons correspond to GuestCtl0.GExcCode (VZ) */
#define KVM_TRACE_EXIT_GEXCCODE_BASE	64
#define KVM_TRACE_EXIT_GPSI		64	/*  0 */
#define KVM_TRACE_EXIT_HC		65	/*  2 */
#define KVM_TRACE_EXIT_GFC		66	/*  1 */

/* Tracepoints for VM exits */
#define kvm_trace_symbol_exit_types					\
	{ KVM_TRACE_EXIT_INT,		"Interrupt" },		\
	{ KVM_TRACE_EXIT_TLBLD,		"TLB (LD)" },		\
	{ KVM_TRACE_EXIT_TLBST,		"TLB (ST)" },		\
	{ KVM_TRACE_EXIT_TLBI,		"TLB Ifetch" },		\
	{ KVM_TRACE_EXIT_TLBMOD,	"TLB Mod" },		\
	{ KVM_TRACE_EXIT_TLBRI,		"TLB RI" },		\
	{ KVM_TRACE_EXIT_TLBXI,		"TLB XI" },		\
	{ KVM_TRACE_EXIT_TLBPE,		"TLB Previlege Error" },\
	{ KVM_TRACE_EXIT_ADDE,		"Address Error" },	\
	{ KVM_TRACE_EXIT_UNALIGN,	"Address unalign" },	\
	{ KVM_TRACE_EXIT_ODB,		"Out boundary" },	\
	{ KVM_TRACE_EXIT_SYSCALL,	"System Call" },	\
	{ KVM_TRACE_EXIT_BP,		"Breakpoint" },		\
	{ KVM_TRACE_EXIT_RI,		"Reserved Inst" },	\
	{ KVM_TRACE_EXIT_IPE,		"Inst prev error" },	\
	{ KVM_TRACE_EXIT_FPDIS,		"FPU disable" },	\
	{ KVM_TRACE_EXIT_LSXDIS,	"LSX disable" },	\
	{ KVM_TRACE_EXIT_LASXDIS,	"LASX disable" },	\
	{ KVM_TRACE_EXIT_FPE,		"FPE" },		\
	{ KVM_TRACE_EXIT_WAIT,		"WAIT" },		\
	{ KVM_TRACE_EXIT_CACHE,		"CACHE" },		\
	{ KVM_TRACE_EXIT_SIGNAL,	"Signal" },		\
	{ KVM_TRACE_EXIT_GPSI,		"GPSI" },		\
	{ KVM_TRACE_EXIT_HC,		"HC" },			\
	{ KVM_TRACE_EXIT_GFC,		"GFC" }

TRACE_EVENT(kvm_exit,
	    TP_PROTO(struct kvm_vcpu *vcpu, unsigned int reason),
	    TP_ARGS(vcpu, reason),
	    TP_STRUCT__entry(
			__field(unsigned long, pc)
			__field(unsigned int, reason)
	    ),

	    TP_fast_assign(
			__entry->pc = vcpu->arch.pc;
			__entry->reason = reason;
	    ),

	    TP_printk("[%s]PC: 0x%08lx",
		      __print_symbolic(__entry->reason,
				       kvm_trace_symbol_exit_types),
		      __entry->pc)
);

#define KVM_TRACE_MFC0		0
#define KVM_TRACE_MTC0		1
#define KVM_TRACE_DMFC0		2
#define KVM_TRACE_DMTC0		3
#define KVM_TRACE_RDHWR		4

#define KVM_TRACE_HWR_COP0	0
#define KVM_TRACE_HWR_HWR	1

#define KVM_TRACE_COP0(REG, SEL)	((KVM_TRACE_HWR_COP0 << 8) |	\
					 ((REG) << 3) | (SEL))
#define KVM_TRACE_HWR(REG, SEL)		((KVM_TRACE_HWR_HWR  << 8) |	\
					 ((REG) << 3) | (SEL))

#define kvm_trace_symbol_hwr_ops				\
	{ KVM_TRACE_MFC0,		"MFC0" },		\
	{ KVM_TRACE_MTC0,		"MTC0" },		\
	{ KVM_TRACE_DMFC0,		"DMFC0" },		\
	{ KVM_TRACE_DMTC0,		"DMTC0" },		\
	{ KVM_TRACE_RDHWR,		"RDHWR" }

#define kvm_trace_symbol_hwr_cop				\
	{ KVM_TRACE_HWR_COP0,		"COP0" },		\
	{ KVM_TRACE_HWR_HWR,		"HWR" }

#define kvm_trace_symbol_hwr_regs				\
	{ KVM_TRACE_COP0(0, 0),	"Index" },		\
	{ KVM_TRACE_COP0(2, 0),	"EntryLo0" },		\
	{ KVM_TRACE_COP0(3, 0),	"EntryLo1" },		\
	{ KVM_TRACE_COP0(4, 0),	"Context" },		\
	{ KVM_TRACE_COP0(4, 2),	"UserLocal" },		\
	{ KVM_TRACE_COP0(5, 0),	"PageMask" },		\
	{ KVM_TRACE_COP0(6, 0),	"Wired" },		\
	{ KVM_TRACE_COP0(7, 0),	"HWREna" },		\
	{ KVM_TRACE_COP0(8, 0),	"BadVAddr" },		\
	{ KVM_TRACE_COP0(9, 0),	"Count" },		\
	{ KVM_TRACE_COP0(10, 0),	"EntryHi" },		\
	{ KVM_TRACE_COP0(11, 0),	"Compare" },		\
	{ KVM_TRACE_COP0(12, 0),	"Status" },		\
	{ KVM_TRACE_COP0(12, 1),	"IntCtl" },		\
	{ KVM_TRACE_COP0(12, 2),	"SRSCtl" },		\
	{ KVM_TRACE_COP0(13, 0),	"Cause" },		\
	{ KVM_TRACE_COP0(14, 0),	"ERA" },		\
	{ KVM_TRACE_COP0(15, 0),	"PRId" },		\
	{ KVM_TRACE_COP0(15, 1),	"EEntry" },		\
	{ KVM_TRACE_COP0(16, 0),	"Config" },		\
	{ KVM_TRACE_COP0(16, 1),	"Config1" },		\
	{ KVM_TRACE_COP0(16, 2),	"Config2" },		\
	{ KVM_TRACE_COP0(16, 3),	"Config3" },		\
	{ KVM_TRACE_COP0(16, 4),	"Config4" },		\
	{ KVM_TRACE_COP0(16, 5),	"Config5" },		\
	{ KVM_TRACE_COP0(16, 7),	"Config7" },		\
	{ KVM_TRACE_COP0(17, 1),	"MAAR" },		\
	{ KVM_TRACE_COP0(17, 2),	"MAARI" },		\
	{ KVM_TRACE_COP0(26, 0),	"ECC" },		\
	{ KVM_TRACE_COP0(30, 0),	"ErrorERA" },		\
	{ KVM_TRACE_COP0(31, 2),	"KScratch1" },		\
	{ KVM_TRACE_COP0(31, 3),	"KScratch2" },		\
	{ KVM_TRACE_COP0(31, 4),	"KScratch3" },		\
	{ KVM_TRACE_COP0(31, 5),	"KScratch4" },		\
	{ KVM_TRACE_COP0(31, 6),	"KScratch5" },		\
	{ KVM_TRACE_COP0(31, 7),	"KScratch6" },		\
	{ KVM_TRACE_HWR(0, 0),		"CPUId" },		\
	{ KVM_TRACE_HWR(1, 0),		"SYNCI_Step" },		\
	{ KVM_TRACE_HWR(2, 0),		"CC" },			\
	{ KVM_TRACE_HWR(3, 0),		"CCRes" },		\
	{ KVM_TRACE_HWR(29, 0),		"ULR" }

TRACE_EVENT(kvm_hwr,
	    TP_PROTO(struct kvm_vcpu *vcpu, unsigned int op, unsigned int reg,
		     unsigned long val),
	    TP_ARGS(vcpu, op, reg, val),
	    TP_STRUCT__entry(
			__field(unsigned long, val)
			__field(u16, reg)
			__field(u8, op)
	    ),

	    TP_fast_assign(
			__entry->val = val;
			__entry->reg = reg;
			__entry->op = op;
	    ),

	    TP_printk("%s %s (%s:%u:%u) 0x%08lx",
		      __print_symbolic(__entry->op,
				       kvm_trace_symbol_hwr_ops),
		      __print_symbolic(__entry->reg,
				       kvm_trace_symbol_hwr_regs),
		      __print_symbolic(__entry->reg >> 8,
				       kvm_trace_symbol_hwr_cop),
		      (__entry->reg >> 3) & 0x1f,
		      __entry->reg & 0x7,
		      __entry->val)
);

#define KVM_TRACE_AUX_RESTORE		0
#define KVM_TRACE_AUX_SAVE			1
#define KVM_TRACE_AUX_ENABLE		2
#define KVM_TRACE_AUX_DISABLE		3
#define KVM_TRACE_AUX_DISCARD		4

#define KVM_TRACE_AUX_FPU		1
#define KVM_TRACE_AUX_LSX		2
#define KVM_TRACE_AUX_FPU_LSX	3
#define KVM_TRACE_AUX_LASX		4
#define KVM_TRACE_AUX_FPU_LSX_LASX	7

#define kvm_trace_symbol_aux_op		\
	{ KVM_TRACE_AUX_RESTORE, "restore" },	\
	{ KVM_TRACE_AUX_SAVE,    "save" },	\
	{ KVM_TRACE_AUX_ENABLE,  "enable" },	\
	{ KVM_TRACE_AUX_DISABLE, "disable" },	\
	{ KVM_TRACE_AUX_DISCARD, "discard" }

#define kvm_trace_symbol_aux_state		\
	{ KVM_TRACE_AUX_FPU,     "FPU" },	\
	{ KVM_TRACE_AUX_LSX,     "LSX" },	\
	{ KVM_TRACE_AUX_LASX,    "LASX" },	\
	{ KVM_TRACE_AUX_FPU_LSX, "FPU & LSX" }, \
	{ KVM_TRACE_AUX_FPU_LSX_LASX, "FPU & LSX & LASX" }

TRACE_EVENT(kvm_aux,
	    TP_PROTO(struct kvm_vcpu *vcpu, unsigned int op,
		     unsigned int state),
	    TP_ARGS(vcpu, op, state),
	    TP_STRUCT__entry(
			__field(unsigned long, pc)
			__field(u8, op)
			__field(u8, state)
	    ),

	    TP_fast_assign(
			__entry->pc = vcpu->arch.pc;
			__entry->op = op;
			__entry->state = state;
	    ),

	    TP_printk("%s %s PC: 0x%08lx",
		      __print_symbolic(__entry->op,
				       kvm_trace_symbol_aux_op),
		      __print_symbolic(__entry->state,
				       kvm_trace_symbol_aux_state),
		      __entry->pc)
);

TRACE_EVENT(kvm_asid_change,
	    TP_PROTO(struct kvm_vcpu *vcpu, unsigned int old_asid,
		     unsigned int new_asid),
	    TP_ARGS(vcpu, old_asid, new_asid),
	    TP_STRUCT__entry(
			__field(unsigned long, pc)
			__field(u8, old_asid)
			__field(u8, new_asid)
	    ),

	    TP_fast_assign(
			__entry->pc = vcpu->arch.pc;
			__entry->old_asid = old_asid;
			__entry->new_asid = new_asid;
	    ),

	    TP_printk("PC: 0x%08lx old: 0x%02x new: 0x%02x",
		      __entry->pc,
		      __entry->old_asid,
		      __entry->new_asid)
);

TRACE_EVENT(kvm_guestid_change,
	    TP_PROTO(struct kvm_vcpu *vcpu, unsigned int guestid),
	    TP_ARGS(vcpu, guestid),
	    TP_STRUCT__entry(
			__field(unsigned int, guestid)
	    ),

	    TP_fast_assign(
			__entry->guestid = guestid;
	    ),

	    TP_printk("GuestID: 0x%02x",
		      __entry->guestid)
);

TRACE_EVENT_FN(kvm_guest_mode_change,
	    TP_PROTO(struct kvm_vcpu *vcpu),
	    TP_ARGS(vcpu),
	    TP_STRUCT__entry(
			__field(unsigned long, era)
			__field(unsigned long, pc)
			__field(unsigned long, badvaddr)
			__field(unsigned long, exst)
			__field(unsigned long, cu)
	    ),

	    TP_fast_assign(
			__entry->era = kvm_read_hw_gcsr(LOONGARCH_CSR_ERA);
			__entry->pc = vcpu->arch.pc;
			__entry->badvaddr = kvm_read_sw_gcsr(vcpu->arch.csr, LOONGARCH_CSR_BADV);
			__entry->exst = kvm_read_sw_gcsr(vcpu->arch.csr, LOONGARCH_CSR_ESTAT);
			__entry->cu = kvm_read_hw_gcsr(LOONGARCH_CSR_EUEN);
	    ),

	    TP_printk("ERA: 0x%08lx PC: 0x%08lx ExSt: 0x%08lx CU: 0x%08lx BadVAddr: 0x%08lx",
		      __entry->era,
		      __entry->pc,
		      __entry->exst,
		      __entry->cu,
		      __entry->badvaddr),

	    kvm_guest_mode_change_trace_reg,
	    kvm_guest_mode_change_trace_unreg
);

#endif /* _TRACE_KVM_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
