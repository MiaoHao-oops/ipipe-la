/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * KVM/LOONGISA: Instruction/Exception emulation
 *
 * Copyright (C) 2020 Loongson  Technologies, Inc.  All rights reserved.
 * Authors: Xing Li <lixing@loongson.cn>
 */

#include <linux/errno.h>
#include <linux/err.h>
#include <linux/ktime.h>
#include <linux/kvm_host.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/bootmem.h>
#include <linux/random.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/cacheops.h>
#include <asm/cpu-info.h>
#include <asm/mmu_context.h>
#include <asm/tlbflush.h>
#include <asm/inst.h>
#include <loongson.h>
#include "interrupt.h"
#include "trace.h"
#include "ls3a.h"

int kvm_loongarch_emul_wait(struct kvm_vcpu *vcpu)
{
	kvm_debug("[%#lx] !!!WAIT!!! (%#lx)\n", vcpu->arch.pc,
		  vcpu->arch.pending_exceptions);

	++vcpu->stat.wait_exits;
	trace_kvm_exit(vcpu, KVM_TRACE_EXIT_WAIT);
	if (!vcpu->arch.pending_exceptions) {
		kvm_save_timer(vcpu);
		vcpu->arch.wait = 1;
		kvm_vcpu_block(vcpu);

		/*
		 * We we are runnable, then definitely go off to user space to
		 * check if any I/O interrupts are pending.
		 */
		if (kvm_check_request(KVM_REQ_UNHALT, vcpu)) {
			kvm_clear_request(KVM_REQ_UNHALT, vcpu);
			vcpu->run->exit_reason = KVM_EXIT_IRQ_WINDOW_OPEN;
		}
	}

	return EMULATE_DONE;
}

int kvm_larch_emu_st(larch_inst inst, struct kvm_vcpu *vcpu)
{
	struct kvm_run *run = vcpu->run;
	u32 rd, op8, opcode;
	unsigned long rd_val = 0;
	void *data = run->mmio.data;
	unsigned long curr_pc;
	int ret = 0;
	struct kvm_ops *kvm_ops = vcpu->kvm->arch.kvm_ops;

	/*
	 * Update PC and hold onto current PC in case there is
	 * an error and we want to rollback the PC
	 */
	curr_pc = vcpu->arch.pc;
	update_pc(&vcpu->arch);

	op8 = (inst.word >> 24) & 0xff;
	run->mmio.phys_addr = kvm_ops->gva_to_gpa(vcpu->arch.host_badvaddr);
	if (run->mmio.phys_addr == KVM_INVALID_ADDR)
		goto out_fail;

	if (op8 < 0x28) {
		/* stptrw/d process */
		rd = inst.reg2i14_format.rd;
		opcode = inst.reg2i14_format.opcode;

		switch (opcode) {
		case stptrd_op:
			run->mmio.len = 8;
			*(u64 *)data = vcpu->arch.gprs[rd];
			kvm_debug("[%#lx] OP_STPTRD: eaddr: %#lx, gpr: %#lx, data: %#llx\n",
				  vcpu->arch.pc, vcpu->arch.host_badvaddr,
				  vcpu->arch.gprs[rd], *(u64 *)data);
			break;
		case stptrw_op:
			run->mmio.len = 4;
			*(u32 *)data = vcpu->arch.gprs[rd];
			kvm_debug("[%#lx] OP_STPTRW: eaddr: %#lx, gpr: %#lx, data: %#x\n",
				  vcpu->arch.pc, vcpu->arch.host_badvaddr,
				  vcpu->arch.gprs[rd], *(u32 *)data);
			break;
		default:
			break;
		}
	} else if (op8 < 0x30) {
		/* st.b/h/w/d  process */
		rd = inst.reg2i12_format.rd;
		opcode = inst.reg2i12_format.opcode;
		rd_val = vcpu->arch.gprs[rd];

		switch (opcode) {
		case std_op:
			run->mmio.len = 8;
			*(u64 *)data = rd_val;

			kvm_debug("[%#lx] OP_STD: eaddr: %#lx, gpr: %#lx, data: %#llx\n",
				  vcpu->arch.pc, vcpu->arch.host_badvaddr,
				  rd_val, *(u64 *)data);
			break;
		case stw_op:
			run->mmio.len = 4;
			*(u32 *)data = rd_val;

			kvm_debug("[%#lx] OP_STW: eaddr: %#lx, gpr: %#lx, data: %#x\n",
				  vcpu->arch.pc, vcpu->arch.host_badvaddr,
				  rd_val, *(u32 *)data);
			break;
		case sth_op:
			run->mmio.len = 2;
			*(u16 *)data = rd_val;

			kvm_debug("[%#lx] OP_STH: eaddr: %#lx, gpr: %#lx, data: %#x\n",
				  vcpu->arch.pc, vcpu->arch.host_badvaddr,
				  rd_val, *(u16 *)data);
			break;
		case stb_op:
			run->mmio.len = 1;
			*(u8 *)data = rd_val;

			kvm_debug("[%#lx] OP_STB: eaddr: %#lx, gpr: %#lx, data: %#x\n",
				  vcpu->arch.pc, vcpu->arch.host_badvaddr,
				  rd_val, *(u8 *)data);
			break;
		default:
			kvm_err("Store not yet supporded (inst=0x%08x)\n",
				inst.word);
			kvm_arch_vcpu_dump_regs(vcpu);
			goto out_fail;
		}
	} else if (op8 == 0x38) {
		/* stxb/h/w/d process */
		rd = inst.reg3_format.rd;
		opcode = inst.reg3_format.opcode;

		switch (opcode) {
		case stxb_op:
			run->mmio.len = 1;
			*(u8 *)data = vcpu->arch.gprs[rd];

			kvm_debug("[%#lx] OP_STXB: eaddr: %#lx, gpr: %#lx, data: %#x\n",
				  vcpu->arch.pc, vcpu->arch.host_badvaddr,
				  vcpu->arch.gprs[rd], *(u8 *)data);
			break;
		case stxh_op:
			run->mmio.len = 2;
			*(u16 *)data = vcpu->arch.gprs[rd];

			kvm_debug("[%#lx] OP_STXH: eaddr: %#lx, gpr: %#lx, data: %#x\n",
				  vcpu->arch.pc, vcpu->arch.host_badvaddr,
				  vcpu->arch.gprs[rd], *(u16 *)data);
			break;
		case stxw_op:
			run->mmio.len = 4;
			*(u32 *)data = vcpu->arch.gprs[rd];

			kvm_debug("[%#lx] OP_STXW: eaddr: %#lx, gpr: %#lx, data: %#x\n",
				  vcpu->arch.pc, vcpu->arch.host_badvaddr,
				  vcpu->arch.gprs[rd], *(u32 *)data);
			break;
		case stxd_op:
			run->mmio.len = 8;
			*(u64 *)data = vcpu->arch.gprs[rd];

			kvm_debug("[%#lx] OP_STXD: eaddr: %#lx, gpr: %#lx, data: %#llx\n",
				  vcpu->arch.pc, vcpu->arch.host_badvaddr,
				  vcpu->arch.gprs[rd], *(u64 *)data);
			break;
		default:
			kvm_err("Store not yet supporded (inst=0x%08x)\n",
				inst.word);
			kvm_arch_vcpu_dump_regs(vcpu);
			goto out_fail;
		}
	} else {
		kvm_err("Store not yet supporded (inst=0x%08x)\n",
			inst.word);
		kvm_arch_vcpu_dump_regs(vcpu);
		goto out_fail;
	}

	/* All MMIO emulate in kernel go through the common interface */
	ret = kvm_io_bus_write(vcpu, KVM_MMIO_BUS, run->mmio.phys_addr,
				run->mmio.len, data);
	if (!ret) {
		vcpu->mmio_needed = 0;
		return EMULATE_DONE;
	}

	run->mmio.is_write = 1;
	vcpu->mmio_needed = 1;
	vcpu->mmio_is_write = 1;

	return EMULATE_DO_MMIO;

out_fail:
	/* Rollback PC if emulation was unsuccessful */
	vcpu->arch.pc = curr_pc;
	return EMULATE_FAIL;
}


int kvm_larch_emu_ld(larch_inst inst, struct kvm_vcpu *vcpu)
{
	unsigned long curr_pc;
	u32 op8, opcode, rd;
	int ret = 0;
	struct kvm_run *run = vcpu->run;
	struct kvm_ops *kvm_ops = vcpu->kvm->arch.kvm_ops;

	/*
	 * Find the resume PC now while we have safe and easy access to the
	 * prior branch instruction, and save it for
	 * kvm_larch_complete_ld() to restore later.
	 */
	curr_pc = vcpu->arch.pc;
	update_pc(&vcpu->arch);

	vcpu->arch.io_pc = vcpu->arch.pc;
	vcpu->arch.pc = curr_pc;

	run->mmio.phys_addr = kvm_ops->gva_to_gpa(vcpu->arch.host_badvaddr);
	if (run->mmio.phys_addr == KVM_INVALID_ADDR)
		return EMULATE_FAIL;

	vcpu->mmio_needed = 2;	/* signed */
	op8 = (inst.word >> 24) & 0xff;

	if (op8 < 0x28) {
		/* ldptr.w/d process */
		rd = inst.reg2i14_format.rd;
		opcode = inst.reg2i14_format.opcode;

		switch (opcode) {
		case ldptrd_op:
			run->mmio.len = 8;
			break;
		case ldptrw_op:
			run->mmio.len = 4;
			break;
		default:
			break;
		}
	} else if (op8 < 0x2f) {
		/* ld.b/h/w/d, ld.bu/hu/wu process */
		rd = inst.reg2i12_format.rd;
		opcode = inst.reg2i12_format.opcode;

		switch (opcode) {
		case ldd_op:
			run->mmio.len = 8;
			break;
		case ldwu_op:
			vcpu->mmio_needed = 1;	/* unsigned */
			run->mmio.len = 4;
			break;
		case ldw_op:
			run->mmio.len = 4;
			break;
		case ldhu_op:
			vcpu->mmio_needed = 1;	/* unsigned */
			run->mmio.len = 2;
			break;
		case ldh_op:
			run->mmio.len = 2;
			break;
		case ldbu_op:
			vcpu->mmio_needed = 1;	/* unsigned */
			run->mmio.len = 1;
			break;
		case ldb_op:
			run->mmio.len = 1;
			break;
		default:
			kvm_err("Load not yet supporded (inst=0x%08x)\n",
				inst.word);
			kvm_arch_vcpu_dump_regs(vcpu);
			vcpu->mmio_needed = 0;
			return EMULATE_FAIL;
		}
	} else if (op8 == 0x38) {
		/* ldxb/h/w/d, ldxb/h/wu, ldgtb/h/w/d, ldleb/h/w/d process */
		rd = inst.reg3_format.rd;
		opcode = inst.reg3_format.opcode;

		switch (opcode) {
		case ldxb_op:
			run->mmio.len = 1;
			break;
		case ldxbu_op:
			run->mmio.len = 1;
			vcpu->mmio_needed = 1;	/* unsigned */
			break;
		case ldxh_op:
			run->mmio.len = 2;
			break;
		case ldxhu_op:
			run->mmio.len = 2;
			vcpu->mmio_needed = 1;	/* unsigned */
			break;
		case ldxw_op:
			run->mmio.len = 4;
			break;
		case ldxwu_op:
			run->mmio.len = 4;
			vcpu->mmio_needed = 1;	/* unsigned */
			break;
		case ldxd_op:
			run->mmio.len = 8;
			break;
		default:
			kvm_err("Load not yet supporded (inst=0x%08x)\n",
				inst.word);
			kvm_arch_vcpu_dump_regs(vcpu);
			vcpu->mmio_needed = 0;
			return EMULATE_FAIL;
		}
	} else {
		kvm_err("Load not yet supporded (inst=0x%08x) @ %lx\n",
			inst.word, vcpu->arch.pc);
		vcpu->mmio_needed = 0;
		return EMULATE_FAIL;
	}

	/* Set for kvm_larch_complete_ld use */
	vcpu->arch.io_gpr = rd;
	ret = kvm_io_bus_read(vcpu, KVM_MMIO_BUS, run->mmio.phys_addr,
						run->mmio.len, run->mmio.data);
	run->mmio.is_write = 0;
	vcpu->mmio_is_write = 0;

	if (!ret) {
		kvm_larch_complete_ld(vcpu, run);
		vcpu->mmio_needed = 0;
		return EMULATE_DONE;
	}
	return EMULATE_DO_MMIO;
}

int kvm_larch_complete_ld(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	unsigned long *gpr = &vcpu->arch.gprs[vcpu->arch.io_gpr];
	enum emulation_result er = EMULATE_DONE;

	/* Restore saved resume PC */
	vcpu->arch.pc = vcpu->arch.io_pc;
	switch (run->mmio.len) {
	case 8:
		*gpr = *(s64 *)run->mmio.data;
		break;

	case 4:
		if (vcpu->mmio_needed == 2) {
			*gpr = *(s32 *)run->mmio.data;
		} else
			*gpr = *(u32 *)run->mmio.data;
		break;

	case 2:
		if (vcpu->mmio_needed == 2)
			*gpr = *(s16 *) run->mmio.data;
		else
			*gpr = *(u16 *)run->mmio.data;

		break;
	case 1:
		if (vcpu->mmio_needed == 2)
			*gpr = *(s8 *) run->mmio.data;
		else
			*gpr = *(u8 *) run->mmio.data;
		break;
	default:
		kvm_err("Bad MMIO length: %d,addr is 0x%lx",
				run->mmio.len, vcpu->arch.host_badvaddr);
		er = EMULATE_FAIL;
		break;
	}

	return er;
}
