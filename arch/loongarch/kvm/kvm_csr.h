#ifndef __LOONGARCH_KVM_CSR_H__
#define __LOONGARCH_KVM_CSR_H__
#include <asm/loongarchregs.h>
#include <asm/kvm_host.h>
#include <linux/uaccess.h>

#define kvm_read_hw_gcsr(id)			gcsr_readq(id)
#define kvm_write_hw_gcsr(csr, id, val)		gcsr_writeq(val, id)

int lvz_getcsr(struct kvm_vcpu *vcpu, unsigned int id, u64 *v, int force);
int lvz_setcsr(struct kvm_vcpu *vcpu, unsigned int id, u64 *v, int force);
unsigned long lvz_gpsi_read_csr(struct kvm_vcpu *vcpu, int csrid);
void lvz_gpsi_write_csr(struct kvm_vcpu *vcpu, int csrid,
	unsigned long val);
void lvz_gpsi_change_csr(struct kvm_vcpu *vcpu, int csrid,
	unsigned long csr_mask, unsigned long val);
int lvz_gpsi_iocsr(larch_inst inst,
		struct kvm_run *run, struct kvm_vcpu *vcpu);

static inline void kvm_save_hw_gcsr(struct loongarch_csrs *csr, int gid)
{
	csr->csrs[gid] = gcsr_readq(gid);
}

static inline void kvm_restore_hw_gcsr(struct loongarch_csrs *csr, int gid)
{
	gcsr_writeq(csr->csrs[gid], gid);
}

static inline unsigned long kvm_read_sw_gcsr(struct loongarch_csrs *csr, int gid)
{
	return csr->csrs[gid];
}

static inline void kvm_write_sw_gcsr(struct loongarch_csrs *csr, int gid, unsigned long val)
{
	csr->csrs[gid] = val;
}

static inline void kvm_set_sw_gcsr(struct loongarch_csrs *csr, int gid, unsigned long val)
{
	csr->csrs[gid] |= val;
}

static inline void kvm_change_sw_gcsr(struct loongarch_csrs *csr, int gid, unsigned mask,
	unsigned long val)
{
	unsigned long _mask = mask;
	csr->csrs[gid] &= ~_mask;
	csr->csrs[gid] |= val & _mask;
}


#define GET_HW_GCSR(id, csrid, v)				\
	do {							\
		if (csrid == id) {				\
			*v = (long)kvm_read_hw_gcsr(csrid);	\
			return 0;				\
		}						\
	} while (0)

#define GET_SW_GCSR(csr, regid, csrid, v)			\
	do {							\
		if (csrid == id) {				\
			*v = kvm_read_sw_gcsr(csr, csrid);	\
			return 0;				\
		}						\
	} while (0)

#define SET_HW_GCSR(csr, id, csrid, v)				\
	do {							\
		if (csrid == id) {				\
			kvm_write_hw_gcsr(csr, csrid, *v);	\
			return 0;				\
		}						\
	} while (0)

#define SET_SW_GCSR(csr, id, csrid, v)				\
	do {							\
		if (csrid == id) {				\
			kvm_write_sw_gcsr(csr, csrid, *v);	\
			return 0;				\
		}						\
	} while (0)

#define ENABLE_PERFCTL_MOD(csr, csrid)						\
	kvm_write_hw_gcsr(csr, csrid, kvm_read_hw_gcsr(csrid) | CSR_PERFCTRL_GMOD)

#define GET_HW_PERF(vcpu_arch, id, csrid)					\
	do {									\
		if (csrid == id) {						\
			write_csr_gcfg(read_csr_gcfg() | CSR_GCFG_GPERF); 	\
			ENABLE_PERFCTL_MOD(csr, LOONGARCH_CSR_PERFCTRL0);	\
			ENABLE_PERFCTL_MOD(csr, LOONGARCH_CSR_PERFCTRL1);	\
			ENABLE_PERFCTL_MOD(csr, LOONGARCH_CSR_PERFCTRL2);	\
			ENABLE_PERFCTL_MOD(csr, LOONGARCH_CSR_PERFCTRL3);	\
			vcpu->arch.aux_inuse |= KVM_LARCH_PERF;    		\
			return (long)kvm_read_hw_gcsr(csrid);			\
		}								\
	} while (0)

#define SET_HW_PERF(vcpu_arch, csr, id, csrid, v)				\
	do {									\
		if (csrid == id) {						\
			write_csr_gcfg(read_csr_gcfg() | CSR_GCFG_GPERF); 	\
			kvm_write_hw_gcsr(csr, csrid, v);			\
			ENABLE_PERFCTL_MOD(csr, LOONGARCH_CSR_PERFCTRL0);	\
			ENABLE_PERFCTL_MOD(csr, LOONGARCH_CSR_PERFCTRL1);	\
			ENABLE_PERFCTL_MOD(csr, LOONGARCH_CSR_PERFCTRL2);	\
			ENABLE_PERFCTL_MOD(csr, LOONGARCH_CSR_PERFCTRL3);	\
			vcpu->arch.aux_inuse |= KVM_LARCH_PERF;		    	\
			return ;						\
		}								\
	} while (0)

int lvz_iocsr_init(struct kvm *kvm);
struct kvm_iocsr_entry *kvm_find_iocsr(struct kvm *kvm, u32 addr);

int lvz_iocsr_set(struct kvm *kvm, struct kvm_iocsr_entry *__user argp);
int lvz_iocsr_get(struct kvm *kvm, struct kvm_iocsr_entry *__user argp);
#endif
