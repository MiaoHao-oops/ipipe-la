/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * KVM/LOONGISA: Interrupts
 * Copyright (C) 2020  Loongson Technologies, Inc.  All rights reserved.
 * Authors: Xing Li <lixing@loongson.cn>
 */

/*
 * LOONGISA Exception Priorities, exceptions (including interrupts) are queued up
 * for the guest in the order specified by their priorities
 */

#define LARCH_INT_SIP0		0
#define LARCH_INT_SIP1		1
#define LARCH_INT_IP0		2
#define LARCH_INT_IP1		3
#define LARCH_INT_IP2		4
#define LARCH_INT_IP3		5
#define LARCH_INT_IP4		6
#define LARCH_INT_IP5		7
#define LARCH_INT_IP6		8
#define LARCH_INT_IP7		9
#define LARCH_INT_PC		10
#define LARCH_INT_TIMER		11
#define LARCH_INT_IPI		12
#define LOONGARCH_EXC_MAX		(LARCH_INT_IPI + 1)
#define LOONGARCH_EXC_IPNUM		(LOONGARCH_EXC_MAX)

/* Controlled by 0x5 guest exst */
#define C_SIP0		(_ULCAST_(1))
#define C_SIP1		(_ULCAST_(1) << 1)
#define C_PC		(_ULCAST_(1) << 10)
#define C_TIMER		(_ULCAST_(1) << 11)
#define C_IPI		(_ULCAST_(1) << 12)
/* Controlled by 0x52 guest exception VIP
 * aligned to exst bit 5~12
 */
#define C_IP0		(_ULCAST_(1))
#define C_IP1		(_ULCAST_(1) << 1)
#define C_IP2		(_ULCAST_(1) << 2)
#define C_IP3		(_ULCAST_(1) << 3)
#define C_IP4		(_ULCAST_(1) << 4)
#define C_IP5		(_ULCAST_(1) << 5)
#define C_IP6		(_ULCAST_(1) << 6)
#define C_IP7		(_ULCAST_(1) << 7)

int kvm_loongarch_pending_timer(struct kvm_vcpu *vcpu);

void kvm_loongarch_deliver_interrupts(struct kvm_vcpu *vcpu);
void irqchip_debug_init(struct kvm *kvm);
void irqchip_debug_destroy(struct kvm *kvm);
