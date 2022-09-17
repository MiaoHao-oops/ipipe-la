/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * KVM/LOONGISA: Interrupt delivery
 *
 * Copyright (C) 2020  Loongson Technologies, Inc.  All rights reserved.
 * Authors: Xing Li <lixing@loongson.cn>
 */

#include <linux/errno.h>
#include <linux/err.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/bootmem.h>
#include <asm/page.h>
#include <asm/cacheflush.h>

#include <linux/kvm_host.h>

#include "interrupt.h"

void kvm_loongarch_deliver_interrupts(struct kvm_vcpu *vcpu)
{
	unsigned long *pending = &vcpu->arch.pending_exceptions;
	unsigned long *pending_clr = &vcpu->arch.pending_exceptions_clr;
	unsigned int priority;
	struct kvm_ops *kvm_ops = vcpu->kvm->arch.kvm_ops;

	if (!(*pending) && !(*pending_clr))
		return;

	if (*pending_clr) {
		priority = __ffs(*pending_clr);
		while (priority <= LOONGARCH_EXC_IPNUM) {
			kvm_ops->irq_clear(vcpu, priority);
			priority = find_next_bit(pending_clr,
					   BITS_PER_BYTE * sizeof(*pending_clr),
					   priority + 1);
		}
	}

	if (*pending) {
		priority = __ffs(*pending);
		while (priority <= LOONGARCH_EXC_IPNUM) {
			kvm_ops->irq_deliver(vcpu, priority);
			priority = find_next_bit(pending,
					       BITS_PER_BYTE * sizeof(*pending),
					       priority + 1);
		}
	}

}

int kvm_loongarch_pending_timer(struct kvm_vcpu *vcpu)
{
	return test_bit(LARCH_INT_TIMER, &vcpu->arch.pending_exceptions);
}
