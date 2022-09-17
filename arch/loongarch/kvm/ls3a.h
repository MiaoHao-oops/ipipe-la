/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * KVM/LOONGISA: Support for hardware virtualization extensions
 *
 * Copyright (C) 2020 Loongson Corp.
 * Authors: Huang Pei <huangpei@loongon.cn>
 * Author: Xing Li, lixing@loongson.cn
 */
#ifndef __KVM_LOONGARCH_LS3A_H__
#define __KVM_LOONGARCH_LS3A_H__

#include <linux/kernel.h>
#include <linux/kvm_host.h>
#include <linux/kvm_para.h>
#include "ls3a_ipi.h"
#include "ls7a_irq.h"
#include "ls3a_ext_irq.h"

#define MASK64_HI56	0xffffffffffffff00ULL
#define MASK64_HI48	0xffffffffffff0000ULL
#define MASK64_HI40	0xffffffffff000000ULL
#define MASK64_HI32	0xffffffff00000000ULL
#define MASK64_HI24	0xffffff0000000000ULL
#define MASK64_HI16	0xffff000000000000ULL
#define MASK64_HI8	0xff00000000000000ULL
#define MASK32_HI24	0xffffff00
#define MASK32_HI16	0xffff0000
#define MASK32_HI8	0xff000000
#define MASK_LO8	0xff
#define MASK_LO16	0xffff
#define MASK_LO24	0xffffff
#define MASK_LO32	0xffffffff
#define MASK_LO40	0xffffffffffULL
#define MASK_LO48	0xffffffffffffULL
#define MASK_LO56	0xffffffffffffffULL

#define MNSEC_PER_SEC	(NSEC_PER_SEC >> 20)
void kvm_own_fpu(struct kvm_vcpu *vcpu);
void kvm_own_lsx(struct kvm_vcpu *vcpu);
void kvm_lose_fpu(struct kvm_vcpu *vcpu);
void kvm_lose_hw_breakpoint(struct kvm_vcpu *vcpu);
void kvm_restore_hw_breakpoint(struct kvm_vcpu *vcpu);
void kvm_own_lasx(struct kvm_vcpu *vcpu);

void kvm_lose_hw_perf(struct kvm_vcpu *vcpu);
void kvm_restore_hw_perf(struct kvm_vcpu *vcpu);

void kvm_save_fpu(struct kvm_vcpu *cpu);
void kvm_restore_fpu(struct kvm_vcpu *cpu);
void kvm_restore_fcsr(struct kvm_vcpu *cpu);
void kvm_save_lsx(struct kvm_vcpu *cpu);
void kvm_restore_lsx(struct kvm_vcpu *cpu);
void kvm_restore_lsx_upper(struct kvm_vcpu *cpu);
void kvm_restore_vcsr(struct kvm_vcpu *cpu);
void kvm_save_lasx(struct kvm_vcpu *cpu);
void kvm_restore_lasx(struct kvm_vcpu *cpu);
void kvm_restore_lasx_upper(struct kvm_vcpu *cpu);

void kvm_acquire_timer(struct kvm_vcpu *vcpu);
void kvm_reset_timer(struct kvm_vcpu *vcpu);
enum hrtimer_restart kvm_count_timeout(struct kvm_vcpu *vcpu);
void kvm_init_timer(struct kvm_vcpu *vcpu, unsigned long hz);
void kvm_restore_timer(struct kvm_vcpu *vcpu);
void kvm_save_timer(struct kvm_vcpu *vcpu);
#endif
