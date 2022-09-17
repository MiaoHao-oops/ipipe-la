/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * KVM/LOONGISA: Support for hardware virtualization extensions
 *
 * Copyright (C) 2020 Loongson  Technologies, Inc.  All rights reserved.
 * Authors: Xing Li <lixing@loongson.cn>
 */

#include <linux/errno.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/preempt.h>
#include <linux/vmalloc.h>
#include <asm/cacheflush.h>
#include <asm/cacheops.h>
#include <asm/cmpxchg.h>
#include <asm/fpu.h>
#include <asm/inst.h>
#include <asm/mmu_context.h>
#include <asm/cacheflush.h>
#include <asm/time.h>
#include <asm/tlb.h>
#include <asm/loongarchregs.h>
#include <asm/numa.h>
#include <asm/watch.h>

#include <linux/kvm_host.h>
#include <loongson.h>
#include <mmzone.h>

#include "interrupt.h"
#include "trace.h"
#include "ls3a.h"
#include "kvm_csr.h"
#include "hw_breakpoint.h"

/* Pointers to last VCPU loaded on each physical CPU */
static struct kvm_vcpu *last_vcpu[NR_CPUS];

static gpa_t lvz_gva_to_gpa_cb(gva_t gva)
{
	/* VZ guest has already converted gva to gpa */
	return gva;
}

/*
 * LOONGSON VZ guest interrupt handling.
 */
static void lvz_queue_irq(struct kvm_vcpu *vcpu, unsigned int priority)
{
	set_bit(priority, &vcpu->arch.pending_exceptions);
	clear_bit(priority, &vcpu->arch.pending_exceptions_clr);
}

static void lvz_dequeue_irq(struct kvm_vcpu *vcpu, unsigned int priority)
{
	clear_bit(priority, &vcpu->arch.pending_exceptions);
	set_bit(priority, &vcpu->arch.pending_exceptions_clr);
}

static void lvz_queue_timer_int(struct kvm_vcpu *vcpu)
{
	lvz_queue_irq(vcpu, LARCH_INT_TIMER);
}

static void lvz_dequeue_timer_int(struct kvm_vcpu *vcpu)
{
	/*
	 * timer expiry is asynchronous to vcpu execution therefore defer guest
	 * csr accesses
	 */
	lvz_dequeue_irq(vcpu, LARCH_INT_TIMER);
}

static void lvz_queue_io_int(struct kvm_vcpu *vcpu, int intr)
{
	if ((intr > 0) && (intr < LOONGARCH_EXC_MAX))
		lvz_queue_irq(vcpu, intr);
}

static void lvz_dequeue_io_int(struct kvm_vcpu *vcpu, int intr)
{
	if ((intr > 0) && (intr < LOONGARCH_EXC_MAX))
		lvz_dequeue_irq(vcpu, intr);
}

static u32 lvz_priority_to_irq[LOONGARCH_EXC_MAX] = {
	[LARCH_INT_TIMER] = C_TIMER,
	[LARCH_INT_IPI]   = C_IPI,
	[LARCH_INT_SIP0]  = C_SIP0,
	[LARCH_INT_SIP1]  = C_SIP1,
	[LARCH_INT_IP0]   = C_IP0,
	[LARCH_INT_IP1]   = C_IP1,
	[LARCH_INT_IP2]   = C_IP2,
	[LARCH_INT_IP3]   = C_IP3,
	[LARCH_INT_IP4]   = C_IP4,
	[LARCH_INT_IP5]   = C_IP5,
	[LARCH_INT_IP6]   = C_IP6,
	[LARCH_INT_IP7]   = C_IP7,
};

static int lvz_irq_deliver(struct kvm_vcpu *vcpu, unsigned int priority)
{
	unsigned int irq = 0;

	clear_bit(priority, &vcpu->arch.pending_exceptions);
	if (priority < LOONGARCH_EXC_MAX)
		irq = lvz_priority_to_irq[priority];

	switch (priority) {
	case LARCH_INT_TIMER:
	case LARCH_INT_IPI:
	case LARCH_INT_SIP0:
	case LARCH_INT_SIP1:
		set_gcsr_estat(irq);
		break;

	case LARCH_INT_IP0:
	case LARCH_INT_IP1:
	case LARCH_INT_IP2:
	case LARCH_INT_IP3:
	case LARCH_INT_IP4:
	case LARCH_INT_IP5:
	case LARCH_INT_IP6:
	case LARCH_INT_IP7:
		set_csr_gintc(irq);
		break;

	default:
		break;
	}

	return 1;
}

static int lvz_irq_clear(struct kvm_vcpu *vcpu, unsigned int priority)
{
	unsigned int irq = 0;

	clear_bit(priority, &vcpu->arch.pending_exceptions_clr);
	if (priority < LOONGARCH_EXC_MAX)
		irq = lvz_priority_to_irq[priority];

	switch (priority) {
	case LARCH_INT_TIMER:
	case LARCH_INT_IPI:
	case LARCH_INT_SIP0:
	case LARCH_INT_SIP1:
		clear_gcsr_estat(irq);
		break;

	case LARCH_INT_IP0:
	case LARCH_INT_IP1:
	case LARCH_INT_IP2:
	case LARCH_INT_IP3:
	case LARCH_INT_IP4:
	case LARCH_INT_IP5:
	case LARCH_INT_IP6:
	case LARCH_INT_IP7:
		clear_csr_gintc(irq);
		break;

	default:
		break;
	}

	return 1;
}

/*
 * LOONGSON VZ guest callback handling.
 */

static int lvz_trap_no_handler(struct kvm_vcpu *vcpu)
{
	u32 *opc = (u32 *) vcpu->arch.pc;
	u64 estat = vcpu->arch.host_estat;
	u32 exccode = (estat & CSR_ESTAT_EXC) >> CSR_ESTAT_EXC_SHIFT;
	unsigned long badvaddr = vcpu->arch.host_badvaddr;
	u32 inst = 0;

	/*
	 *  Fetch the instruction.
	 */
	kvm_get_badinstr(&vcpu->arch, &inst);

	kvm_err("Exception Code: %d not handled @ PC: %p, inst: 0x%08x BadVaddr: %#lx estat: %lx\n",
		exccode, opc, inst, badvaddr,
		(ulong)read_gcsr_estat());
	kvm_arch_vcpu_dump_regs(vcpu);
	vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
	return RESUME_HOST;
}

static int lvz_gpsi_csr(larch_inst inst,
			struct kvm_run *run, struct kvm_vcpu *vcpu)
{
	enum emulation_result er = EMULATE_DONE;
	u32 rd, rj;
	u32 csr_val;
	unsigned long csr_mask;
	unsigned long val = 0;

	/*
	 * CSR value mask imm
	 * rj = 0 means csrrd
	 * rj = 1 means csrwr
	 * rj != 0,1 means csrxchg
	 */
	rd = inst.reg2csr_format.rd;
	rj = inst.reg2csr_format.rj;
	csr_val = inst.reg2csr_format.csr;

	/* Process CSR ops */
	if (rj == 0) {
		/* process csrrd */
		val = lvz_gpsi_read_csr(vcpu, csr_val);
		if (er != EMULATE_FAIL)
			vcpu->arch.gprs[rd] = val;

	} else if (rj == 1) {
		/* process csrwr */
		val = vcpu->arch.gprs[rd];
		lvz_gpsi_write_csr(vcpu, csr_val, val);

	} else {
		/* process csrxchg */
		val = vcpu->arch.gprs[rd];
		csr_mask = vcpu->arch.gprs[rj];
		lvz_gpsi_change_csr(vcpu, csr_val, csr_mask, val);
	}

	return er;
}

static int lvz_gpsi_cache(larch_inst inst, struct kvm_run *run, struct kvm_vcpu *vcpu)
{
	u32 cache, op_inst, op, base;
	s16 offset;
	struct kvm_vcpu_arch *arch = &vcpu->arch;
	unsigned long va;

	/*
	 * Update PC and hold onto current PC in case there is
	 * an error and we want to rollback the PC
	 */

	base = inst.reg2i12_format.rj;
	op_inst = inst.reg2i12_format.rd;
	offset = inst.reg2i12_format.simmediate;
	cache = op_inst & CacheOp_Cache;
	op = op_inst & CacheOp_Op;

	va = arch->gprs[base] + offset;

	kvm_debug("CACHE (cache: %#x, op: %#x, base[%d]: %#lx, offset: %#x\n",
		  cache, op, base, arch->gprs[base], offset);

	if (op != CacheOp_User_Defined)
		return EMULATE_DONE;

	kvm_err("CACHE (cache: %#x, op: %#x, base[%d]: %#lx, offset: %#x\n",
		cache, op, base, arch->gprs[base], offset);

	return EMULATE_FAIL;
}

static int lvz_trap_handle_gpsi(struct kvm_vcpu *vcpu)
{
	enum emulation_result er = EMULATE_DONE;
	struct kvm_run *run = vcpu->run;
	larch_inst inst;
	unsigned long curr_pc;
	int rd, rj;
	unsigned int cpucfg_no;

	/*
	 *  Fetch the instruction.
	 */
	kvm_get_badinstr(&vcpu->arch, &inst.word);

	curr_pc = vcpu->arch.pc;
	update_pc(&vcpu->arch);

	er = EMULATE_FAIL;
	switch (((inst.word >> 24) & 0xff)) {
	case 0x0:
		/* cpucfg PSI */
		if (inst.reg2_format.opcode == 0x1B) {
			rd = inst.reg2_format.rd;
			rj = inst.reg2_format.rj;
			++vcpu->stat.lvz_cpucfg_exits;
			cpucfg_no = vcpu->arch.gprs[rj];
			vcpu->arch.gprs[rd] = vcpu->kvm->arch.cpucfgs.cpucfg[cpucfg_no];
			if (vcpu->arch.gprs[rd] == 0) {
				/*
				 * Fallback to get host cpucfg info, this is just for
				 * compatible with older qemu.
				 */
				vcpu->arch.gprs[rd] = read_cpucfg(cpucfg_no);
				/* Ignore VZ for guest */
				if (cpucfg_no == 2)
					vcpu->arch.gprs[rd] &= ~CPUCFG2_LVZP;
			}
			er = EMULATE_DONE;
		}
		break;
	case 0x4:
		/* csr PSI */
		er = lvz_gpsi_csr(inst, run, vcpu);
		break;
	case 0x6:
		/* iocsr,cache,wait PSI */
		switch (((inst.word >> 22) & 0x3ff)) {
		case 0x18:
			/* cache PSI */
			er = lvz_gpsi_cache(inst, run, vcpu);
			trace_kvm_exit(vcpu, KVM_TRACE_EXIT_CACHE);
			break;
		case 0x19:
			/* iocsr wait PSI */
			switch (((inst.word >> 15) & 0x1ffff)) {
			case 0xc90:
				/* iocsr PSI */
				er = lvz_gpsi_iocsr(inst, run, vcpu);
				break;
			case wait_op:
				/* wait PSI */
				er = kvm_loongarch_emul_wait(vcpu);
				break;
			default:
				er = EMULATE_FAIL;
				break;
			}
			break;
		default:
			er = EMULATE_FAIL;
			break;
		}
		break;
	default:
		er = EMULATE_FAIL;
		break;
	}

	/* Rollback PC only if emulation was unsuccessful */
	if (er == EMULATE_FAIL) {
		kvm_err("[%#lx]%s: unsupported gpsi instruction 0x%08x\n",
			curr_pc, __func__, inst.word);

		kvm_arch_vcpu_dump_regs(vcpu);
		vcpu->arch.pc = curr_pc;
	}
	return er;
}

static int lvz_trap_handle_gsfc(struct kvm_vcpu *vcpu)
{
	return EMULATE_DONE;
}

static int lvz_trap_handle_hc(struct kvm_vcpu *vcpu)
{
	enum emulation_result er;
	larch_inst inst;
	unsigned long curr_pc;

	kvm_get_badinstr(&vcpu->arch, &inst.word);

	/*
	 * Update PC and hold onto current PC in case there is
	 * an error and we want to rollback the PC
	 */
	curr_pc = vcpu->arch.pc;
	update_pc(&vcpu->arch);

	er = kvm_loongarch_emul_hypcall(vcpu, inst);
	if (er == EMULATE_FAIL || er == EMULATE_DEBUG)
		vcpu->arch.pc = curr_pc;

	return er;
}

/* Execute cpucfg instruction will tirgger PSI,
 * Also the access to unimplemented csrs 0x15
 * 0x16, 0x50~0x53, 0x80, 0x81, 0x90~0x95, 0x98
 * 0xc0~0xff, 0x100~0x109, 0x500~0x502,
 * cache_op, wait_op iocsr ops the same */
static int lvz_trap_handle_psi(struct kvm_vcpu *vcpu)
{
	enum emulation_result er = EMULATE_DONE;
	int ret = RESUME_GUEST;

	vcpu->arch.is_hypcall = 0;

	er = lvz_trap_handle_gpsi(vcpu);

	if (er == EMULATE_DONE) {
		ret = RESUME_GUEST;
	} else if (er == EMULATE_DO_MMIO) {
		vcpu->run->exit_reason = KVM_EXIT_MMIO;
		ret = RESUME_HOST;
	} else {
		kvm_err("%s internal error\n", __func__);
		vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		ret = RESUME_HOST;
	}
	return ret;
}

static int lvz_trap_handle_hypcall(struct kvm_vcpu *vcpu)
{
	enum emulation_result er = EMULATE_DONE;
	int ret = RESUME_GUEST;

	vcpu->arch.is_hypcall = 0;
	er = lvz_trap_handle_hc(vcpu);
	if (er == EMULATE_DONE) {
		ret = RESUME_GUEST;
	} else if (er == EMULATE_HYPERCALL) {
		ret = kvm_loongarch_handle_hypcall(vcpu);
	} else if (er == EMULATE_DEBUG) {
		vcpu->run->exit_reason = KVM_EXIT_DEBUG;
		ret = RESUME_HOST;
	} else {
		kvm_err("%s internal error\n", __func__);
		vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		ret = RESUME_HOST;
	}
	return ret;
}

static int lvz_trap_handle_ghfc(struct kvm_vcpu *vcpu)
{
	return EMULATE_DONE;
}

static int lvz_trap_handle_gfc(struct kvm_vcpu *vcpu)
{
	enum emulation_result er = EMULATE_DONE;
	int ret = RESUME_GUEST;
	u32 subcode = (vcpu->arch.host_estat & CSR_ESTAT_ESUBCODE) >>
						CSR_ESTAT_ESUBCODE_SHIFT;

	vcpu->arch.is_hypcall = 0;

	if (subcode == EXCSUBCODE_GCSC)
		er = lvz_trap_handle_gsfc(vcpu);
	else if (subcode == EXCSUBCODE_GCHC)
		er = lvz_trap_handle_ghfc(vcpu);
	else
		er = EMULATE_FAIL;

	if (er == EMULATE_DONE) {
		ret = RESUME_GUEST;
	} else if (er == EMULATE_DO_MMIO) {
		vcpu->run->exit_reason = KVM_EXIT_MMIO;
		ret = RESUME_HOST;
	} else {
		kvm_err("%s internal error\n", __func__);
		vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		ret = RESUME_HOST;
	}
	return ret;
}

/**
 * lvz_trap_handle_cop_unusuable() - Guest used unusable coprocessor.
 * @vcpu:	Virtual CPU context.
 *
 * Handle when the guest attempts to use a coprocessor which hasn't been allowed
 * by the root context.
 */
static int lvz_trap_handle_cop_unusable(struct kvm_vcpu *vcpu)
{
	struct kvm_run *run = vcpu->run;
	u64 estat = vcpu->arch.host_estat;
	enum emulation_result er = EMULATE_FAIL;
	int ret = RESUME_GUEST;

	if (((estat & CSR_ESTAT_EXC) >> CSR_ESTAT_EXC_SHIFT) == EXCCODE_FPDIS) {
		/*
		 * If guest FPU not present, the FPU operation should have been
		 * treated as a reserved instruction!
		 * If FPU already in use, we shouldn't get this at all.
		 */
		if (WARN_ON(!kvm_loongarch_guest_has_fpu(&vcpu->arch) ||
			    vcpu->arch.aux_inuse & KVM_LARCH_FPU)) {
			preempt_enable();
			return EMULATE_FAIL;
		}

		kvm_own_fpu(vcpu);
		er = EMULATE_DONE;
	}
	/* other coprocessors not handled */

	switch (er) {
	case EMULATE_DONE:
		ret = RESUME_GUEST;
		break;

	case EMULATE_FAIL:
		kvm_err("Guest CU%d: unusable\n", (unsigned int)(estat & CSR_ESTAT_EXC) >> CSR_ESTAT_EXC_SHIFT);
		run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		ret = RESUME_HOST;
		break;

	default:
		BUG();
	}
	return ret;
}

/**
 * lvz_trap_handle_lsx_disabled() - Guest used LSX while disabled in root.
 * @vcpu:	Virtual CPU context.
 *
 * Handle when the guest attempts to use LSX when it is disabled in the root
 * context.
 */
static int lvz_trap_handle_lsx_disabled(struct kvm_vcpu *vcpu)
{
	struct kvm_run *run = vcpu->run;

	/*
	 * If LSX not present or not exposed to guest, the LSX operation
	 * should have been treated as a reserved instruction!
	 * If LSX already in use, we shouldn't get this at all.
	 */
	if (!kvm_loongarch_guest_has_lsx(&vcpu->arch) ||
	    !(read_gcsr_coprocessor() & CSR_EUEN_LSXEN) ||
	    vcpu->arch.aux_inuse & KVM_LARCH_LSX) {
		kvm_err("%s internal error, lsx %d guest cu %llx aux %x",
			__func__, kvm_loongarch_guest_has_lsx(&vcpu->arch),
			read_gcsr_coprocessor(), vcpu->arch.aux_inuse);
		run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		return RESUME_HOST;
	}

	kvm_own_lsx(vcpu);

	return RESUME_GUEST;
}

bool kvm_loongarch_guest_has_lasx(struct kvm_vcpu *vcpu)
{
      return (!__builtin_constant_p(cpu_has_lasx) || cpu_has_lasx) &&
		vcpu->arch.lsx_enabled && vcpu->kvm->arch.cpucfg_lasx;
}

/**
 * lvz_trap_handle_lasx_disabled() - Guest used LASX while disabled in root.
 * @vcpu:	Virtual CPU context.
 *
 * Handle when the guest attempts to use LASX when it is disabled in the root
 * context.
 */
static int lvz_trap_handle_lasx_disabled(struct kvm_vcpu *vcpu)
{
	struct kvm_run *run = vcpu->run;

	/*
	 * If LASX not present or not exposed to guest, the LASX operation
	 * should have been treated as a reserved instruction!
	 * If LASX already in use, we shouldn't get this at all.
	 */
	if (!kvm_loongarch_guest_has_lasx(vcpu) ||
	    !(read_gcsr_coprocessor() & CSR_EUEN_LSXEN) ||
	    !(read_gcsr_coprocessor() & CSR_EUEN_LASXEN) ||
	    vcpu->arch.aux_inuse & KVM_LARCH_LASX) {
		kvm_err("%s internal error, lasx %d guest cu %llx aux %x",
			__func__, kvm_loongarch_guest_has_lasx(vcpu),
			read_gcsr_coprocessor(), vcpu->arch.aux_inuse);
		run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		return RESUME_HOST;
	}

	kvm_own_lasx(vcpu);

	return RESUME_GUEST;
}


static int lvz_trap_handle_tlb_ld_miss(struct kvm_vcpu *vcpu)
{
	struct kvm_run *run = vcpu->run;
	u32 *opc = (u32 *)vcpu->arch.pc;
	ulong badvaddr = vcpu->arch.host_badvaddr;
	larch_inst inst;
	enum emulation_result er = EMULATE_DONE;
	int ret = RESUME_GUEST;

	if (kvm_loongarch_handle_lvz_root_tlb_fault(badvaddr, vcpu, false)) {
		/* A code fetch fault doesn't count as an MMIO */
		if (kvm_is_ifetch_fault(&vcpu->arch)) {
			kvm_err("%s ifetch error addr:%lx\n", __func__, vcpu->arch.host_badvaddr);
			run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
			return RESUME_HOST;
		}

		/* Fetch the instruction */
		kvm_get_badinstr(&vcpu->arch, &inst.word);

		/* Treat as MMIO */
		er = kvm_larch_emu_ld(inst, vcpu);
		if (er == EMULATE_FAIL) {
			kvm_err("Guest Emulate Load from MMIO space failed: PC: %p, BadVaddr: %#lx\n",
				opc, badvaddr);
			run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		}
	}

	if (er == EMULATE_DONE) {
		ret = RESUME_GUEST;
	} else if (er == EMULATE_DO_MMIO) {
		run->exit_reason = KVM_EXIT_MMIO;
		ret = RESUME_HOST;
	} else {
		run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		ret = RESUME_HOST;
	}
	return ret;
}

static int lvz_trap_handle_tlb_st_miss(struct kvm_vcpu *vcpu)
{
	struct kvm_run *run = vcpu->run;
	u32 *opc = (u32 *)vcpu->arch.pc;
	ulong badvaddr = vcpu->arch.host_badvaddr;
	larch_inst inst;
	enum emulation_result er = EMULATE_DONE;
	int ret = RESUME_GUEST;

	if (kvm_loongarch_handle_lvz_root_tlb_fault(badvaddr, vcpu, true)) {
		/* Fetch the instruction */
		kvm_get_badinstr(&vcpu->arch, &inst.word);

		/* Treat as MMIO */
		er = kvm_larch_emu_st(inst, vcpu);
		if (er == EMULATE_FAIL) {
			kvm_err("Guest Emulate Store to MMIO space failed: PC: %p, BadVaddr: %#lx\n",
				opc, badvaddr);
			run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		}
	}

	if (er == EMULATE_DONE) {
		ret = RESUME_GUEST;
	} else if (er == EMULATE_DO_MMIO) {
		run->exit_reason = KVM_EXIT_MMIO;
		ret = RESUME_HOST;
	} else {
		run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		ret = RESUME_HOST;
	}
	return ret;
}

static int lvz_get_one_reg(struct kvm_vcpu *vcpu,
			      const struct kvm_one_reg *reg, s64 *v)
{
	struct loongarch_csrs *csr = vcpu->arch.csr;
	int reg_idx, ret;

	if ((reg->id & KVM_IOC_CSRID(0)) == KVM_IOC_CSRID(0)) {
		reg_idx = KVM_GET_IOC_CSRIDX(reg->id);
		ret = lvz_getcsr(vcpu, reg_idx, v, 0);
		if (ret == 0)
			return ret;
	}

	switch (reg->id) {
	case KVM_REG_LOONGARCH_COUNTER:
		*v = drdtime() + vcpu->kvm->arch.stablecounter_gftoffset;
		break;
	default:
		if ((reg->id & KVM_REG_LOONGARCH_MASK) != KVM_REG_LOONGARCH_CSR)
			return -EINVAL;

		reg_idx = KVM_GET_IOC_CSRIDX(reg->id);
		if (reg_idx < CSR_ALL_SIZE) {
			*v = kvm_read_sw_gcsr(csr, reg_idx);
			kvm_debug("%s id 0x%llx reg_idx:0x%x \n", \
					__func__, reg->id, reg_idx);
		} else {
			return -EINVAL;
		}
	}
	return 0;
}

static int lvz_set_one_reg(struct kvm_vcpu *vcpu,
			      const struct kvm_one_reg *reg,
			      s64 v)
{
	struct loongarch_csrs *csr = vcpu->arch.csr;
	int ret = 0;
	unsigned long flags;
	u64 val;
	int reg_idx;

	val = v;
	if ((reg->id & KVM_IOC_CSRID(0)) == KVM_IOC_CSRID(0)) {
		reg_idx = KVM_GET_IOC_CSRIDX(reg->id);
		ret = lvz_setcsr(vcpu, reg_idx, &val, 0);
		if (ret == 0)
			return ret;
	}

	switch (reg->id) {
	case KVM_REG_LOONGARCH_COUNTER:
		local_irq_save(flags);
		/*
		 * gftoffset is relative with board, not vcpu
		 * only set for the first time for smp system
		 */
		if (vcpu->vcpu_id == 0)
			vcpu->kvm->arch.stablecounter_gftoffset = (signed long)(v - drdtime());
		write_csr_gcntc((ulong)vcpu->kvm->arch.stablecounter_gftoffset);
		local_irq_restore(flags);
		break;
	case KVM_REG_LOONGARCH_VCPU_RESET:
		kvm_reset_timer(vcpu);
		if (vcpu->vcpu_id == 0)
			kvm_enable_ls3a_extirq(vcpu->kvm, false);
		memset(&vcpu->arch.pending_exceptions, 0, sizeof(vcpu->arch.pending_exceptions));
		memset(&vcpu->arch.pending_exceptions_clr, 0, sizeof(vcpu->arch.pending_exceptions_clr));
		break;
	default:
		if ((reg->id & KVM_REG_LOONGARCH_MASK) != KVM_REG_LOONGARCH_CSR)
			return -EINVAL;

		reg_idx = KVM_GET_IOC_CSRIDX(reg->id);
		if (reg_idx < CSR_ALL_SIZE) {
			kvm_write_sw_gcsr(csr, reg_idx, v);
			kvm_debug("%s id 0x%llx reg_idx:0x%x \n", \
					__func__, reg->id, reg_idx);
		} else {
			return -EINVAL;
		}
	}
	return ret;
}

#define guestid_cache(cpu)	(cpu_data[cpu].guestid_cache)
static void lvz_get_new_guestid(unsigned long cpu, struct kvm_vcpu *vcpu)
{
	unsigned long guestid = guestid_cache(cpu);

	if (!(++guestid & GUESTID_MASK)) {

		if (!guestid)		/* fix version if needed */
			guestid = GUESTID_FIRST_VERSION;

		++guestid;		/* guestid 0 reserved for root */

		/* start new guestid cycle */
		kvm_lvz_local_flush_roottlb_all_guests();
	}

	guestid_cache(cpu) = guestid;
	vcpu->arch.vzguestid[cpu] = guestid;
}

/* Returns 1 if the guest TLB may be clobbered */
static int lvz_check_requests(struct kvm_vcpu *vcpu, int cpu)
{
	int ret = 0;
	int i;

	if (!kvm_request_pending(vcpu))
		return 0;

	if (kvm_check_request(KVM_REQ_TLB_FLUSH, vcpu)) {
		/* Drop all GuestIDs for this VCPU */
		for_each_possible_cpu(i)
			vcpu->arch.vzguestid[i] = 0;
		/* This will clobber guest TLB contents too */
		ret = 1;
	}

	return ret;
}

static void lvz_vcpu_load_tlb(struct kvm_vcpu *vcpu, int cpu)
{
	bool migrated;
	unsigned int gstinfo_gidmask, gstinfo_gid = 0;

	/*
	 * Are we entering guest context on a different CPU to last time?
	 * If so, the VCPU's guest TLB state on this CPU may be stale.
	 */
	migrated = (vcpu->arch.last_exec_cpu != cpu);
	vcpu->arch.last_exec_cpu = cpu;

	/*
	 * Check if our GuestID is of an older version and thus invalid.
	 *
	 * We also discard the stored GuestID if we've executed on
	 * another CPU, as the guest mappings may have changed without
	 * hypervisor knowledge.
	 */
	gstinfo_gidmask = GUESTID_MASK << CSR_GSTAT_GID_SHIFT;
	if (migrated ||
			(vcpu->arch.vzguestid[cpu] ^ guestid_cache(cpu)) &
			GUESTID_VERSION_MASK) {
		lvz_get_new_guestid(cpu, vcpu);
		trace_kvm_guestid_change(vcpu,
				vcpu->arch.vzguestid[cpu]);
	}
	gstinfo_gid = (vcpu->arch.vzguestid[cpu] & GUESTID_MASK) <<
		CSR_GSTAT_GID_SHIFT;

	/* Restore GSTAT(0x50).GuestID */
	change_csr_gstat(gstinfo_gidmask, gstinfo_gid);
}

static int lvz_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	struct loongarch_csrs *csr = vcpu->arch.csr;
	bool migrated, all;

	/*
	 * Have we migrated to a different CPU?
	 * If so, any old guest TLB state may be stale.
	 */
	migrated = (vcpu->arch.last_sched_cpu != cpu);

	/*
	 * Was this the last VCPU to run on this CPU?
	 * If not, any old guest state from this VCPU will have been clobbered.
	 */
	all = migrated || (last_vcpu[cpu] != vcpu);
	last_vcpu[cpu] = vcpu;

	/*
	 * Restore timer state regardless, as e.g. Cause.TI can change over time
	 * if left unmaintained.
	 */
	kvm_restore_timer(vcpu);

	/* Set MC bit if we want to trace guest mode changes */

	/* Control guest page CCA attribute */
	change_csr_gcfg(CSR_GCFG_MATC_MASK, CSR_GCFG_MATC_ROOT);

	/* Clear hardware breakpoint csr if needed */
	clear_current_thread_hwbp(vcpu);

	/* Restore guest used hardware breakpoint csr */
	kvm_restore_hw_breakpoint(vcpu);

	/* Restore hypervisor gdb used hardware breakpoint csr */
	restore_hypervisor_hw_breakpoint(vcpu);

	/* Restore hardware perf csr */
	kvm_restore_hw_perf(vcpu);

#ifdef CONFIG_PARAVIRT
	kvm_make_request(KVM_REQ_RECORD_STEAL, vcpu);
#endif
	/* Don't bother restoring registers multiple times unless necessary */
	if (!all)
		return 0;

	write_csr_gcntc((ulong)vcpu->kvm->arch.stablecounter_gftoffset);

	/*
	 * Restore config registers first, as some implementations restrict
	 * writes to other registers when the corresponding feature bits aren't
	 * set. For example Status.CU1 cannot be set unless Config1.FP is set.
	 */
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_CRMD);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_PRMD);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_EUEN);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_MISC);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_ECFG);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_ERA);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_BADV);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_BADI);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_EENTRY);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_TLBIDX);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_TLBEHI);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_TLBELO0);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_TLBELO1);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_ASID);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_PGDL);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_PGDH);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_PWCTL0);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_PWCTL1);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_STLBPGSIZE);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_RVACFG);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_CPUID);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_KS0);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_KS1);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_KS2);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_KS3);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_KS4);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_KS5);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_KS6);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_KS7);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_TMID);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_CNTC);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_TLBRENTRY);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_TLBRBADV);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_TLBRERA);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_TLBRSAVE);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_TLBRELO0);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_TLBRELO1);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_TLBREHI);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_TLBRPRMD);

	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_DMWIN0);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_DMWIN1);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_DMWIN2);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_DMWIN3);

	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_LLBCTL);

	/* restore Root.Guestexcept from unused Guest guestexcept register */
	write_csr_gintc(csr->csrs[LOONGARCH_CSR_GINTC]);

	/*
	 * We should clear linked load bit to break interrupted atomics. This
	 * prevents a SC on the next VCPU from succeeding by matching a LL on
	 * the previous VCPU.
	 */
	if (vcpu->kvm->created_vcpus > 1)
		set_gcsr_llbctl(CSR_LLBCTL_WCLLB);

	return 0;
}

static int lvz_vcpu_put(struct kvm_vcpu *vcpu, int cpu)
{
	struct loongarch_csrs *csr = vcpu->arch.csr;

	kvm_lose_fpu(vcpu);
	kvm_lose_hw_breakpoint(vcpu);

	/* If hypervisor debug guest or guest itself use hw breakpoint,
	 * should clear registers and install current thread environment */
	clear_hypervisor_guest_hwbp(vcpu);
	kvm_lose_hw_perf(vcpu);

	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_CRMD);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_PRMD);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_EUEN);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_MISC);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_ECFG);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_ERA);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_BADV);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_BADI);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_EENTRY);

	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_TLBIDX);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_TLBEHI);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_TLBELO0);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_TLBELO1);

	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_ASID);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_PGDL);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_PGDH);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_PGD);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_PWCTL0);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_PWCTL1);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_STLBPGSIZE);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_RVACFG);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_CPUID);

	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_PRCFG1);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_PRCFG2);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_PRCFG3);

	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_KS0);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_KS1);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_KS2);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_KS3);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_KS4);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_KS5);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_KS6);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_KS7);

	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_TMID);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_CNTC);

	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_LLBCTL);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_TLBRENTRY);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_TLBRBADV);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_TLBRERA);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_TLBRSAVE);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_TLBRELO0);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_TLBRELO1);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_TLBREHI);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_TLBRPRMD);

	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_DMWIN0);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_DMWIN1);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_DMWIN2);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_DMWIN3);

	kvm_save_timer(vcpu);

	/* save Root.Guestexcept in unused Guest guestexcept register */
	csr->csrs[LOONGARCH_CSR_GINTC] = read_csr_gintc();
	return 0;
}

static int lvz_vcpu_init(struct kvm_vcpu *vcpu)
{
	int i;

	for_each_possible_cpu(i)
		vcpu->arch.vzguestid[i] = 0;

	return 0;
}

static void lvz_vcpu_uninit(struct kvm_vcpu *vcpu)
{
	int cpu;

	/*
	 * If the VCPU is freed and reused as another VCPU, we don't want the
	 * matching pointer wrongly hanging around in last_vcpu[].
	 */
	for_each_possible_cpu(cpu) {
		if (last_vcpu[cpu] == vcpu)
			last_vcpu[cpu] = NULL;
	}
}

static int lvz_vcpu_setup(struct kvm_vcpu *vcpu)
{
	struct loongarch_csrs *csr = vcpu->arch.csr;
	unsigned long timer_hz;

	timer_hz = ((ulong)read_cpucfg(0x4) * (ulong)(read_cpucfg(0x5) & 0xffff))/
		((read_cpucfg(0x5) >> 16) & 0xffff);
	kvm_init_timer(vcpu, timer_hz);

	/*
	 * Initialize guest register state to valid architectural reset state.
	 */

	/* Set Initialize mode for GUEST */
	kvm_write_sw_gcsr(csr, LOONGARCH_CSR_CRMD, CSR_CRMD_DA);

	/* Set cpuid */
	kvm_write_sw_gcsr(csr, LOONGARCH_CSR_TMID, vcpu->vcpu_id);

	/* start with no pending virtual guest interrupts */
	csr->csrs[LOONGARCH_CSR_GINTC] = 0;

	return 0;
}

static void lvz_flush_shadow_all(struct kvm *kvm)
{
	/* Flush GuestID for each VCPU individually */
	kvm_flush_remote_tlbs(kvm);
}

static void lvz_flush_shadow_memslot(struct kvm *kvm,
					const struct kvm_memory_slot *slot)
{
	lvz_flush_shadow_all(kvm);
}

static void lvz_vcpu_reenter(struct kvm_run *run, struct kvm_vcpu *vcpu)
{
	int cpu = smp_processor_id();

	lvz_check_requests(vcpu, cpu);
	lvz_vcpu_load_tlb(vcpu, cpu);
}

static int lvz_vcpu_run(struct kvm_run *run, struct kvm_vcpu *vcpu)
{
	int cpu = smp_processor_id();
	int r;

	kvm_acquire_timer(vcpu);
	/* Check if we have any exceptions/interrupts pending */
	kvm_loongarch_deliver_interrupts(vcpu);

	lvz_check_requests(vcpu, cpu);
	lvz_vcpu_load_tlb(vcpu, cpu);
	kvm_enable_hypervisor_hwbp(vcpu);
	r = vcpu->arch.vcpu_run(run, vcpu);

	return r;
}

static int lvz_trap_handle_break(struct kvm_vcpu *vcpu)
{
	uint32_t fwps, mwps;

	fwps = csr_readq(LOONGARCH_CSR_FWPS);
	mwps = csr_readq(LOONGARCH_CSR_MWPS);
	if (fwps & 0xff)
		csr_writeq(fwps, LOONGARCH_CSR_FWPS);
	if (mwps & 0xff)
		csr_writeq(mwps, LOONGARCH_CSR_MWPS);
	vcpu->run->debug.arch.exception = EXCCODE_WATCH;
	vcpu->run->debug.arch.fwps = fwps;
	vcpu->run->debug.arch.mwps = mwps;
	vcpu->run->exit_reason = KVM_EXIT_DEBUG;
	return RESUME_HOST;
}

exit_handle_fn lvz_exit_handlers[] = {
	[EXCCODE_RSV] = lvz_trap_no_handler,
	[EXCCODE_TLBL] = lvz_trap_handle_tlb_ld_miss,
	[EXCCODE_TLBS] = lvz_trap_handle_tlb_st_miss,
	[EXCCODE_TLBI] = lvz_trap_handle_tlb_ld_miss,
	[EXCCODE_TLBM] = lvz_trap_handle_tlb_st_miss,
	[EXCCODE_TLBRI] = lvz_trap_handle_tlb_ld_miss,
	[EXCCODE_TLBXI] = lvz_trap_handle_tlb_ld_miss,
	[EXCCODE_TLBPE ... EXCCODE_IPE] = lvz_trap_no_handler,
	[EXCCODE_FPDIS] = lvz_trap_handle_cop_unusable,
	[EXCCODE_LSXDIS] = lvz_trap_handle_lsx_disabled,
	[EXCCODE_LASXDIS] = lvz_trap_handle_lasx_disabled,
	[EXCCODE_FPE] = lvz_trap_no_handler,
	[EXCCODE_WATCH] = lvz_trap_handle_break,
	[EXCCODE_BTDIS] = lvz_trap_no_handler,
	[EXCCODE_BTE] = lvz_trap_no_handler,
	[EXCCODE_PSI] = lvz_trap_handle_psi,
	[EXCCODE_HYP] = lvz_trap_handle_hypcall,
	[EXCCODE_GCM] = lvz_trap_handle_gfc,
	[EXCCODE_SE ... (EXCCODE_INT_START - 1)] = lvz_trap_no_handler,
};

static struct kvm_ops kvm_lvz_ops = {
	.vcpu_init = lvz_vcpu_init,
	.vcpu_uninit = lvz_vcpu_uninit,
	.vcpu_setup = lvz_vcpu_setup,
	.flush_shadow_all = lvz_flush_shadow_all,
	.flush_shadow_memslot = lvz_flush_shadow_memslot,
	.gva_to_gpa = lvz_gva_to_gpa_cb,
	.queue_timer_int = lvz_queue_timer_int,
	.dequeue_timer_int = lvz_dequeue_timer_int,
	.queue_io_int = lvz_queue_io_int,
	.dequeue_io_int = lvz_dequeue_io_int,
	.irq_deliver = lvz_irq_deliver,
	.irq_clear = lvz_irq_clear,
	.get_one_reg = lvz_get_one_reg,
	.set_one_reg = lvz_set_one_reg,
	.vcpu_load = lvz_vcpu_load,
	.vcpu_put = lvz_vcpu_put,
	.vcpu_run = lvz_vcpu_run,
	.vcpu_reenter = lvz_vcpu_reenter,
};

int kvm_lvz_ops_init(struct kvm *kvm)
{
	kvm->arch.kvm_ops = &kvm_lvz_ops;
	return 0;
}
