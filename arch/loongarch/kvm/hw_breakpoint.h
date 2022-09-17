#ifndef KVM_HW_BREAKPOINT_H
#define KVM_HW_BREAKPOINT_H
#include <linux/sched/task_stack.h>
#include <asm/loongarchregs.h>
#include <asm/kvm_host.h>
#include "kvm_csr.h"
#include "asm/watch.h"

/* config fwpc/mwpc debug csr for guest */
#define kvm_enable_hw_breakpoint(hw_breakpoint_csr)	\
	do {						\
		int csr_val;				\
		csr_val = csr_readq(hw_breakpoint_csr);	\
		csr_val |= (csr_val & 0x3f) << 16;	\
		csr_writeq(csr_val, hw_breakpoint_csr);	\
	} while (0)

#define CASE_GPSI_WRITE_DATA_BREAKPOINT(vcpu, csr, regid, csrid, val)	\
	do {								\
		if (regid == csrid) {					\
			kvm_enable_hw_breakpoint(LOONGARCH_CSR_MWPC);	\
			kvm_write_hw_gcsr(csr, csrid, val);		\
			vcpu->arch.aux_inuse |= KVM_LARCH_DATA_HWBP;	\
			return ;                                	\
		}							\
	} while (0)

#define CASE_GPSI_WRITE_INST_BREAKPOINT(vcpu, csr, regid, csrid, val)	\
	do {								\
		if (regid == csrid) {					\
			kvm_enable_hw_breakpoint(LOONGARCH_CSR_FWPC);	\
			kvm_write_hw_gcsr(csr, csrid, val);		\
			vcpu->arch.aux_inuse |= KVM_LARCH_INST_HWBP;	\
			return ;                                	\
		}							\
	} while (0)

static inline void disable_data_hwbp(void)
{
	int clear_mwpc_mask = ~0xF0000;
	csr_writeq(csr_readq(LOONGARCH_CSR_MWPC) & clear_mwpc_mask, LOONGARCH_CSR_MWPC);
}

static inline void disable_inst_hwbp(void)
{
	int clear_fwpc_mask = ~0xF0000;
	csr_writeq(csr_readq(LOONGARCH_CSR_FWPC) & clear_fwpc_mask, LOONGARCH_CSR_FWPC);
}

static inline void enable_data_hwbp(void)
{
	kvm_enable_hw_breakpoint(LOONGARCH_CSR_MWPC);
}

static inline void enable_inst_hwbp(void)
{
	kvm_enable_hw_breakpoint(LOONGARCH_CSR_FWPC);
}

static inline void kvm_save_data_hwbp(struct loongarch_csrs *csr)
{
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_DB0ADDR);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_DB0MASK);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_DB0CTL);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_DB0ASID);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_DB1ADDR);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_DB1MASK);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_DB1CTL);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_DB1ASID);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_DB2ADDR);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_DB2MASK);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_DB2CTL);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_DB2ASID);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_DB3ADDR);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_DB3MASK);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_DB3CTL);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_DB3ASID);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_DB4ADDR);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_DB4MASK);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_DB4CTL);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_DB4ASID);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_DB5ADDR);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_DB5MASK);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_DB5CTL);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_DB5ASID);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_DB6ADDR);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_DB6MASK);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_DB6CTL);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_DB6ASID);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_DB7ADDR);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_DB7MASK);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_DB7CTL);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_DB7ASID);
}

static inline void kvm_save_inst_hwbp(struct loongarch_csrs *csr)
{
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_IB0ADDR);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_IB0MASK);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_IB0CTL);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_IB0ASID);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_IB1ADDR);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_IB1MASK);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_IB1CTL);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_IB1ASID);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_IB2ADDR);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_IB2MASK);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_IB2CTL);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_IB2ASID);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_IB3ADDR);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_IB3MASK);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_IB3CTL);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_IB3ASID);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_IB4ADDR);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_IB4MASK);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_IB4CTL);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_IB4ASID);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_IB5ADDR);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_IB5MASK);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_IB5CTL);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_IB5ASID);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_IB6ADDR);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_IB6MASK);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_IB6CTL);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_IB6ASID);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_IB7ADDR);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_IB7MASK);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_IB7CTL);
	kvm_save_hw_gcsr(csr, LOONGARCH_CSR_IB7ASID);
}

static inline void kvm_restore_data_hwbp(struct loongarch_csrs *csr)
{
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_DB0ADDR);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_DB0MASK);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_DB0CTL);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_DB0ASID);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_DB1ADDR);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_DB1MASK);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_DB1CTL);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_DB1ASID);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_DB2ADDR);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_DB2MASK);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_DB2CTL);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_DB2ASID);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_DB3ADDR);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_DB3MASK);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_DB3CTL);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_DB3ASID);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_DB4ADDR);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_DB4MASK);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_DB4CTL);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_DB4ASID);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_DB5ADDR);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_DB5MASK);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_DB5CTL);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_DB5ASID);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_DB6ADDR);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_DB6MASK);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_DB6CTL);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_DB6ASID);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_DB7ADDR);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_DB7MASK);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_DB7CTL);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_DB7ASID);
}

static inline void kvm_restore_inst_hwbp(struct loongarch_csrs *csr)
{
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_IB0ADDR);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_IB0MASK);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_IB0CTL);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_IB0ASID);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_IB1ADDR);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_IB1MASK);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_IB1CTL);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_IB1ASID);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_IB2ADDR);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_IB2MASK);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_IB2CTL);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_IB2ASID);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_IB3ADDR);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_IB3MASK);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_IB3CTL);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_IB3ASID);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_IB4ADDR);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_IB4MASK);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_IB4CTL);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_IB4ASID);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_IB5ADDR);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_IB5MASK);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_IB5CTL);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_IB5ASID);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_IB6ADDR);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_IB6MASK);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_IB6CTL);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_IB6ASID);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_IB7ADDR);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_IB7MASK);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_IB7CTL);
	kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_IB7ASID);
}

static inline void clear_current_thread_hwbp(struct kvm_vcpu *vcpu)
{
	if (vcpu->guest_debug & KVM_GUESTDBG_USE_HW_BP || vcpu->arch.aux_inuse & KVM_LARCH_HWBP) {
		if (test_bit(TIF_LOAD_WATCH, &task_thread_info(current)->flags)) {
			loongarch_clear_watch_registers();
		}
	}
}

static inline void clear_hypervisor_guest_hwbp(struct kvm_vcpu *vcpu)
{
	if (vcpu->guest_debug & KVM_GUESTDBG_USE_HW_BP || vcpu->arch.aux_inuse & KVM_LARCH_HWBP) {
		loongarch_clear_watch_registers();
		/* Install hardware breakpoint csr if needed */
		if (test_bit(TIF_LOAD_WATCH, &task_thread_info(current)->flags)) {
			loongarch_install_watch_registers(current);
		} else if (vcpu->guest_debug & KVM_GUESTDBG_USE_HW_BP) {
			csr_xchgq(0, CSR_PRMD_PWE, LOONGARCH_CSR_PRMD);
		}
	}
}

static inline void kvm_enable_hypervisor_hwbp(struct kvm_vcpu *vcpu)
{
	if (vcpu->guest_debug & KVM_GUESTDBG_USE_HW_BP) {
		csr_xchgq(CSR_PRMD_PWE, CSR_PRMD_PWE, LOONGARCH_CSR_PRMD);
	}
}

static inline void restore_hypervisor_hw_breakpoint(struct kvm_vcpu *vcpu)
{
	int i;
	/* enable hw breakpoint */
	if (vcpu->guest_debug & KVM_GUESTDBG_USE_HW_BP) {
		if (vcpu->arch.guest_debug.inst_bp_nums > 0) {
			for (i = 0; i < vcpu->arch.guest_debug.inst_bp_nums; i++) {
				watch_csrwr(vcpu->arch.guest_debug.inst_breakpoint[i].addr, LOONGARCH_CSR_IB0ADDR + 8 * i);
				watch_csrwr(vcpu->arch.guest_debug.inst_breakpoint[i].mask, LOONGARCH_CSR_IB0MASK + 8 * i);
				watch_csrwr(vcpu->arch.guest_debug.inst_breakpoint[i].asid, LOONGARCH_CSR_IB0ASID + 8 * i);
				watch_csrwr(vcpu->arch.guest_debug.inst_breakpoint[i].ctrl, LOONGARCH_CSR_IB0CTL + 8 * i);
			}
		}
		if (vcpu->arch.guest_debug.data_bp_nums > 0) {
			for (i = 0; i < vcpu->arch.guest_debug.data_bp_nums; i++) {
				watch_csrwr(vcpu->arch.guest_debug.data_breakpoint[i].addr, LOONGARCH_CSR_DB0ADDR + 8 * i);
				watch_csrwr(vcpu->arch.guest_debug.data_breakpoint[i].mask, LOONGARCH_CSR_DB0MASK + 8 * i);
				watch_csrwr(vcpu->arch.guest_debug.data_breakpoint[i].asid, LOONGARCH_CSR_DB0ASID + 8 * i);
				watch_csrwr(vcpu->arch.guest_debug.data_breakpoint[i].ctrl, LOONGARCH_CSR_DB0CTL + 8 * i);
			}
		}
	}
}
#endif
