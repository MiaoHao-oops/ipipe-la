/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * KVM/LOONGISA: Hypercall handling.
 *
 * Copyright (C) 2020 Loongson  Technologies, Inc.  All rights reserved.
 * Authors: Xing Li <lixing@loongson.cn>
 */

#include <linux/kernel.h>
#include <linux/kvm_host.h>
#include <linux/sched/stat.h>
#include <asm/kvm_para.h>
#include <asm/paravirt.h>
#include "ls3a.h"

int kvm_virt_ipi(struct kvm_vcpu *vcpu)
{
	int ret = 0;
	u64 ipi_bitmap;
	unsigned int min, action, cpu;

	ipi_bitmap = vcpu->arch.gprs[REG_A1];
	min = vcpu->arch.gprs[REG_A2];
	action = vcpu->arch.gprs[REG_A3];

	if (ipi_bitmap) {
		cpu = find_first_bit((void *)&ipi_bitmap, BITS_PER_LONG);
		while (cpu < BITS_PER_LONG) {
			kvm_helper_send_ipi(vcpu, cpu + min, action);
			cpu = find_next_bit((void *)&ipi_bitmap, BITS_PER_LONG, cpu + 1);
		}
	}

	return ret;
}

int kvm_save_notify(struct kvm_vcpu *vcpu)
{
	unsigned long num, id, data;

	int ret = 0;

	num = vcpu->arch.gprs[REG_A0];
	id = vcpu->arch.gprs[REG_A1];
	data = vcpu->arch.gprs[REG_A2];

	switch (id) {
	case KVM_FEATURE_STEAL_TIME:
		if (!sched_info_on())
			break;
		vcpu->arch.st.guest_addr = data;
		kvm_debug("cpu :%d addr:%lx\n", vcpu->vcpu_id, data);
		vcpu->arch.st.last_steal = current->sched_info.run_delay;
		kvm_make_request(KVM_REQ_RECORD_STEAL, vcpu);
		break;
	default:
		break;
	};

	return ret;
};

int kvm_loongarch_pv_feature(struct kvm_vcpu *vcpu)
{
	int feature = vcpu->arch.gprs[REG_A1];
	int ret = KVM_RET_NOT_SUPPORTED;
	switch (feature) {
	case KVM_FEATURE_STEAL_TIME:
		if (sched_info_on())
			ret = KVM_RET_SUC;
		break;
	case KVM_FEATURE_MULTI_IPI:
		ret = KVM_RET_SUC;
		break;
	default:
		break;
	}
	return ret;
}

/*
 * Only SWDBG(SoftWare DeBug) could stop vm, code other than 0 is ignored.
 */
int kvm_loongarch_emul_hypcall(struct kvm_vcpu *vcpu,
		union loongarch_instruction inst)
{
	unsigned int code = inst.reg0i15_format.simmediate;
	int ret = EMULATE_DONE;

	if (vcpu->kvm->arch.hypcall_check) {
		kvm_info("[%#lx] HYPCALL %#03x\n", vcpu->arch.pc, code);
		/* Makesue hypcall work ok, useful for unit tests */
		vcpu->kvm->arch.hypcall_check = 0;
	}

	switch (code) {
	case KVM_HC_CODE_SERIVCE:
		ret = EMULATE_HYPERCALL;
		break;
	case KVM_HC_CODE_SWDBG:
		ret = EMULATE_DEBUG;
		break;
	default:
		kvm_info("[%#lx] HYPCALL %#03x unsupported\n", vcpu->arch.pc, code);
		break;
	}

	return ret;
}

/*
 * hypcall emulation always return to guest, Caller should check retval.
 */
int kvm_loongarch_handle_hypcall(struct kvm_vcpu *vcpu)
{
	unsigned long func = vcpu->arch.gprs[REG_A0];
	int hyp_ret = KVM_RET_NOT_SUPPORTED;

	switch (func) {
	case KVM_HC_FUNC_FEATURE:
		hyp_ret = kvm_loongarch_pv_feature(vcpu);
		break;
	case KVM_HC_FUNC_NOTIFY:
		hyp_ret = kvm_save_notify(vcpu);
		break;
	case KVM_HC_FUNC_IPI:
		hyp_ret = kvm_virt_ipi(vcpu);
		break;
	default:
		kvm_info("[%#lx] hvc func:%#lx unsupported\n", vcpu->arch.pc, func);
		break;
	};

	vcpu->arch.gprs[REG_V0] = hyp_ret;

	return RESUME_GUEST;
}
