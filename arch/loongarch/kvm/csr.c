#include <linux/kvm_host.h>
#include <asm/inst.h>
#include <asm/loongarchregs.h>
#include <asm/numa.h>
#include <loongson.h>

#include "ls3a.h"
#include "kvm_csr.h"
#include "hw_breakpoint.h"

#define CASE_GPSI_READ_SW_GCSR(csr, regid, csrid) \
	do {                                          \
		if (regid == csrid) {                     \
			return kvm_read_sw_gcsr(csr, csrid);  \
		}                                         \
	} while (0)

unsigned long lvz_gpsi_read_csr(struct kvm_vcpu *vcpu, int csrid)
{
	struct loongarch_csrs *csr = vcpu->arch.csr;
	unsigned long val = 0;

	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_MCSR0);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_MCSR1);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_MCSR2);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_MCSR3);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_MCSR8);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_MCSR9);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_MCSR10);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_MCSR24);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_UCAWIN);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_UCAWIN0_LO);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_UCAWIN0_HI);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_UCAWIN1_LO);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_UCAWIN1_HI);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_UCAWIN2_LO);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_UCAWIN2_HI);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_UCAWIN3_HI);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_UCAWIN3_HI);

	/*
	 * If not config fwpc/mwpc for guest return csr sw value,
	 * when configed return hardware breakpoint value
	 */
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_MWPS);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_DB0ADDR);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_DB0MASK);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_DB0CTL);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_DB0ASID);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_DB1ADDR);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_DB1MASK);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_DB1CTL);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_DB1ASID);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_DB2ADDR);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_DB2MASK);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_DB2CTL);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_DB2ASID);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_DB3ADDR);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_DB3MASK);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_DB3CTL);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_DB3ASID);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_DB4ADDR);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_DB4MASK);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_DB4CTL);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_DB4ASID);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_DB5ADDR);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_DB5MASK);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_DB5CTL);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_DB5ASID);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_DB6ADDR);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_DB6MASK);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_DB6CTL);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_DB6ASID);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_DB7ADDR);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_DB7MASK);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_DB7CTL);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_DB7ASID);

	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_FWPS);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_IB0ADDR);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_IB0MASK);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_IB0CTL);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_IB0ASID);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_IB1ADDR);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_IB1MASK);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_IB1CTL);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_IB1ASID);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_IB2ADDR);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_IB2MASK);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_IB2CTL);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_IB2ASID);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_IB3ADDR);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_IB3MASK);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_IB3CTL);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_IB3ASID);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_IB4ADDR);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_IB4MASK);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_IB4CTL);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_IB4ASID);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_IB5ADDR);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_IB5MASK);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_IB5CTL);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_IB5ASID);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_IB6ADDR);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_IB6MASK);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_IB6CTL);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_IB6ASID);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_IB7ADDR);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_IB7MASK);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_IB7CTL);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_IB7ASID);

	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_ERRCTL);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_ERRINFO1);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_ERRINFO2);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_MERRENTRY);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_MERRERA);
	CASE_GPSI_READ_SW_GCSR(csr, csrid, LOONGARCH_CSR_ERRSAVE);

	GET_HW_PERF(vcpu->arch, csrid, LOONGARCH_CSR_PERFCTRL0);
	GET_HW_PERF(vcpu->arch, csrid, LOONGARCH_CSR_PERFCNTR0);
	GET_HW_PERF(vcpu->arch, csrid, LOONGARCH_CSR_PERFCTRL1);
	GET_HW_PERF(vcpu->arch, csrid, LOONGARCH_CSR_PERFCNTR1);
	GET_HW_PERF(vcpu->arch, csrid, LOONGARCH_CSR_PERFCTRL2);
	GET_HW_PERF(vcpu->arch, csrid, LOONGARCH_CSR_PERFCNTR2);
	GET_HW_PERF(vcpu->arch, csrid, LOONGARCH_CSR_PERFCTRL3);
	GET_HW_PERF(vcpu->arch, csrid, LOONGARCH_CSR_PERFCNTR3);

	switch (csrid) {
	case LOONGARCH_CSR_IMPCTL1:
		val = read_csr_impctl1();
		kvm_write_sw_gcsr(csr, LOONGARCH_CSR_IMPCTL1, val);
	case LOONGARCH_CSR_MWPC:
		return csr_readq(LOONGARCH_CSR_MWPC);
	case LOONGARCH_CSR_FWPC:
		return csr_readq(LOONGARCH_CSR_FWPC);
	default:
		val = 0;
		if (csrid < 4096)
			val = kvm_read_sw_gcsr(csr, csrid);
		kvm_info("Unsupport csr %x read @ %lx\n",
					csrid, vcpu->arch.pc);
		break;
	}

	return val;
}

#define CASE_GPSI_WRITE_SW_GCSR(csr, regid, csrid, val) \
	do {                                                \
		if (regid == csrid) {                           \
			kvm_write_sw_gcsr(csr, csrid, val);         \
			return ;                                    \
		}                                               \
	} while (0)

void lvz_gpsi_write_csr(struct kvm_vcpu *vcpu, int csrid,
	unsigned long val)
{
	struct loongarch_csrs *csr = vcpu->arch.csr;
	unsigned long flags;

	CASE_GPSI_WRITE_SW_GCSR(csr, csrid, LOONGARCH_CSR_MCSR0, val);
	CASE_GPSI_WRITE_SW_GCSR(csr, csrid, LOONGARCH_CSR_MCSR1, val);
	CASE_GPSI_WRITE_SW_GCSR(csr, csrid, LOONGARCH_CSR_MCSR2, val);
	CASE_GPSI_WRITE_SW_GCSR(csr, csrid, LOONGARCH_CSR_MCSR3, val);
	CASE_GPSI_WRITE_SW_GCSR(csr, csrid, LOONGARCH_CSR_MCSR8, val);
	CASE_GPSI_WRITE_SW_GCSR(csr, csrid, LOONGARCH_CSR_MCSR9, val);
	CASE_GPSI_WRITE_SW_GCSR(csr, csrid, LOONGARCH_CSR_MCSR10, val);
	CASE_GPSI_WRITE_SW_GCSR(csr, csrid, LOONGARCH_CSR_MCSR24, val);
	CASE_GPSI_WRITE_SW_GCSR(csr, csrid, LOONGARCH_CSR_UCAWIN, val);
	CASE_GPSI_WRITE_SW_GCSR(csr, csrid, LOONGARCH_CSR_UCAWIN0_LO, val);
	CASE_GPSI_WRITE_SW_GCSR(csr, csrid, LOONGARCH_CSR_UCAWIN0_HI, val);
	CASE_GPSI_WRITE_SW_GCSR(csr, csrid, LOONGARCH_CSR_UCAWIN1_LO, val);
	CASE_GPSI_WRITE_SW_GCSR(csr, csrid, LOONGARCH_CSR_UCAWIN1_HI, val);
	CASE_GPSI_WRITE_SW_GCSR(csr, csrid, LOONGARCH_CSR_UCAWIN2_LO, val);
	CASE_GPSI_WRITE_SW_GCSR(csr, csrid, LOONGARCH_CSR_UCAWIN2_HI, val);
	CASE_GPSI_WRITE_SW_GCSR(csr, csrid, LOONGARCH_CSR_UCAWIN3_LO, val);
	CASE_GPSI_WRITE_SW_GCSR(csr, csrid, LOONGARCH_CSR_UCAWIN3_HI, val);

	CASE_GPSI_WRITE_SW_GCSR(csr, csrid, LOONGARCH_CSR_ERRCTL, val);
	CASE_GPSI_WRITE_SW_GCSR(csr, csrid, LOONGARCH_CSR_ERRINFO1, val);
	CASE_GPSI_WRITE_SW_GCSR(csr, csrid, LOONGARCH_CSR_ERRINFO2, val);
	CASE_GPSI_WRITE_SW_GCSR(csr, csrid, LOONGARCH_CSR_MERRENTRY, val);
	CASE_GPSI_WRITE_SW_GCSR(csr, csrid, LOONGARCH_CSR_MERRERA, val);
	CASE_GPSI_WRITE_SW_GCSR(csr, csrid, LOONGARCH_CSR_ERRSAVE, val);

	/* Config fwpc/mwpc when guest write hardware breakpoint */
	CASE_GPSI_WRITE_DATA_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_DB0ADDR, val);
	CASE_GPSI_WRITE_DATA_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_DB0MASK, val);
	CASE_GPSI_WRITE_DATA_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_DB0CTL, val);
	CASE_GPSI_WRITE_DATA_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_DB0ASID, val);
	CASE_GPSI_WRITE_DATA_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_DB1ADDR, val);
	CASE_GPSI_WRITE_DATA_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_DB1MASK, val);
	CASE_GPSI_WRITE_DATA_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_DB1CTL, val);
	CASE_GPSI_WRITE_DATA_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_DB1ASID, val);
	CASE_GPSI_WRITE_DATA_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_DB2ADDR, val);
	CASE_GPSI_WRITE_DATA_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_DB2MASK, val);
	CASE_GPSI_WRITE_DATA_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_DB2CTL, val);
	CASE_GPSI_WRITE_DATA_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_DB2ASID, val);
	CASE_GPSI_WRITE_DATA_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_DB3ADDR, val);
	CASE_GPSI_WRITE_DATA_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_DB3MASK, val);
	CASE_GPSI_WRITE_DATA_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_DB3CTL, val);
	CASE_GPSI_WRITE_DATA_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_DB3ASID, val);
	CASE_GPSI_WRITE_DATA_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_DB4ADDR, val);
	CASE_GPSI_WRITE_DATA_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_DB4MASK, val);
	CASE_GPSI_WRITE_DATA_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_DB4CTL, val);
	CASE_GPSI_WRITE_DATA_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_DB4ASID, val);
	CASE_GPSI_WRITE_DATA_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_DB5ADDR, val);
	CASE_GPSI_WRITE_DATA_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_DB5MASK, val);
	CASE_GPSI_WRITE_DATA_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_DB5CTL, val);
	CASE_GPSI_WRITE_DATA_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_DB5ASID, val);
	CASE_GPSI_WRITE_DATA_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_DB6ADDR, val);
	CASE_GPSI_WRITE_DATA_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_DB6MASK, val);
	CASE_GPSI_WRITE_DATA_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_DB6CTL, val);
	CASE_GPSI_WRITE_DATA_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_DB6ASID, val);
	CASE_GPSI_WRITE_DATA_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_DB7ADDR, val);
	CASE_GPSI_WRITE_DATA_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_DB7MASK, val);
	CASE_GPSI_WRITE_DATA_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_DB7CTL, val);
	CASE_GPSI_WRITE_DATA_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_DB7ASID, val);

	CASE_GPSI_WRITE_INST_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_IB0ADDR, val);
	CASE_GPSI_WRITE_INST_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_IB0MASK, val);
	CASE_GPSI_WRITE_INST_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_IB0CTL, val);
	CASE_GPSI_WRITE_INST_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_IB0ASID, val);
	CASE_GPSI_WRITE_INST_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_IB1ADDR, val);
	CASE_GPSI_WRITE_INST_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_IB1MASK, val);
	CASE_GPSI_WRITE_INST_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_IB1CTL, val);
	CASE_GPSI_WRITE_INST_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_IB1ASID, val);
	CASE_GPSI_WRITE_INST_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_IB2ADDR, val);
	CASE_GPSI_WRITE_INST_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_IB2MASK, val);
	CASE_GPSI_WRITE_INST_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_IB2CTL, val);
	CASE_GPSI_WRITE_INST_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_IB2ASID, val);
	CASE_GPSI_WRITE_INST_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_IB3ADDR, val);
	CASE_GPSI_WRITE_INST_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_IB3MASK, val);
	CASE_GPSI_WRITE_INST_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_IB3CTL, val);
	CASE_GPSI_WRITE_INST_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_IB3ASID, val);
	CASE_GPSI_WRITE_INST_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_IB4ADDR, val);
	CASE_GPSI_WRITE_INST_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_IB4MASK, val);
	CASE_GPSI_WRITE_INST_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_IB4CTL, val);
	CASE_GPSI_WRITE_INST_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_IB4ASID, val);
	CASE_GPSI_WRITE_INST_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_IB5ADDR, val);
	CASE_GPSI_WRITE_INST_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_IB5MASK, val);
	CASE_GPSI_WRITE_INST_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_IB5CTL, val);
	CASE_GPSI_WRITE_INST_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_IB5ASID, val);
	CASE_GPSI_WRITE_INST_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_IB6ADDR, val);
	CASE_GPSI_WRITE_INST_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_IB6MASK, val);
	CASE_GPSI_WRITE_INST_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_IB6CTL, val);
	CASE_GPSI_WRITE_INST_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_IB6ASID, val);
	CASE_GPSI_WRITE_INST_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_IB7ADDR, val);
	CASE_GPSI_WRITE_INST_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_IB7MASK, val);
	CASE_GPSI_WRITE_INST_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_IB7CTL, val);
	CASE_GPSI_WRITE_INST_BREAKPOINT(vcpu, csr, csrid, LOONGARCH_CSR_IB7ASID, val);

	SET_HW_PERF(vcpu->arch, csr, csrid, LOONGARCH_CSR_PERFCTRL0, val);
	SET_HW_PERF(vcpu->arch, csr, csrid, LOONGARCH_CSR_PERFCNTR0, val);
	SET_HW_PERF(vcpu->arch, csr, csrid, LOONGARCH_CSR_PERFCTRL1, val);
	SET_HW_PERF(vcpu->arch, csr, csrid, LOONGARCH_CSR_PERFCNTR1, val);
	SET_HW_PERF(vcpu->arch, csr, csrid, LOONGARCH_CSR_PERFCTRL2, val);
	SET_HW_PERF(vcpu->arch, csr, csrid, LOONGARCH_CSR_PERFCNTR2, val);
	SET_HW_PERF(vcpu->arch, csr, csrid, LOONGARCH_CSR_PERFCTRL3, val);
	SET_HW_PERF(vcpu->arch, csr, csrid, LOONGARCH_CSR_PERFCNTR3, val);

	switch (csrid) {
	case LOONGARCH_CSR_IMPCTL1:
		kvm_set_sw_gcsr(csr, csrid, val);
		break;
	case LOONGARCH_CSR_IMPCTL2:
		local_irq_save(flags);
		if (val & CSR_FLUSH_MTLB)
			kvm_loongarch_clear_guest_mtlb();
		if (val & CSR_FLUSH_STLB)
			kvm_loongarch_clear_guest_stlb();
		if (val & CSR_FLUSH_DTLB)
			write_csr_impctl2(CSR_FLUSH_DTLB);
		if (val & CSR_FLUSH_ITLB)
			write_csr_impctl2(CSR_FLUSH_ITLB);
		if (val & CSR_FLUSH_BTAC)
			write_csr_impctl2(CSR_FLUSH_BTAC);
		local_irq_restore(flags);
		break;
	default:
		if (csrid < 4096)
			kvm_write_sw_gcsr(csr, csrid, val);
		kvm_info("Unsupport csr %x write @ %lx\n",
					csrid, vcpu->arch.pc);
		break;
	}
}

#define CASE_GPSI_CHANGE_SW_GCSR(csr, regid, csrid, mask, val) \
	do {                                                       \
		if (regid == csrid) {                                  \
			kvm_change_sw_gcsr(csr, csrid, mask, val);         \
			return ;                                           \
		}                                                      \
	} while (0)

void lvz_gpsi_change_csr(struct kvm_vcpu *vcpu, int csrid,
	unsigned long csr_mask, unsigned long val)
{
	struct loongarch_csrs *csr = vcpu->arch.csr;

	CASE_GPSI_CHANGE_SW_GCSR(csr, csrid, LOONGARCH_CSR_IMPCTL1, csr_mask, val);
	CASE_GPSI_CHANGE_SW_GCSR(csr, csrid, LOONGARCH_CSR_MCSR0, csr_mask, val);
	CASE_GPSI_CHANGE_SW_GCSR(csr, csrid, LOONGARCH_CSR_MCSR1, csr_mask, val);
	CASE_GPSI_CHANGE_SW_GCSR(csr, csrid, LOONGARCH_CSR_MCSR2, csr_mask, val);
	CASE_GPSI_CHANGE_SW_GCSR(csr, csrid, LOONGARCH_CSR_MCSR3, csr_mask, val);
	CASE_GPSI_CHANGE_SW_GCSR(csr, csrid, LOONGARCH_CSR_MCSR8, csr_mask, val);
	CASE_GPSI_CHANGE_SW_GCSR(csr, csrid, LOONGARCH_CSR_MCSR9, csr_mask, val);
	CASE_GPSI_CHANGE_SW_GCSR(csr, csrid, LOONGARCH_CSR_MCSR10, csr_mask, val);
	CASE_GPSI_CHANGE_SW_GCSR(csr, csrid, LOONGARCH_CSR_MCSR24, csr_mask, val);
	CASE_GPSI_CHANGE_SW_GCSR(csr, csrid, LOONGARCH_CSR_UCAWIN, csr_mask, val);
	CASE_GPSI_CHANGE_SW_GCSR(csr, csrid, LOONGARCH_CSR_UCAWIN0_LO, csr_mask, val);
	CASE_GPSI_CHANGE_SW_GCSR(csr, csrid, LOONGARCH_CSR_UCAWIN0_HI, csr_mask, val);
	CASE_GPSI_CHANGE_SW_GCSR(csr, csrid, LOONGARCH_CSR_UCAWIN1_LO, csr_mask, val);
	CASE_GPSI_CHANGE_SW_GCSR(csr, csrid, LOONGARCH_CSR_UCAWIN1_HI, csr_mask, val);
	CASE_GPSI_CHANGE_SW_GCSR(csr, csrid, LOONGARCH_CSR_UCAWIN2_LO, csr_mask, val);
	CASE_GPSI_CHANGE_SW_GCSR(csr, csrid, LOONGARCH_CSR_UCAWIN2_HI, csr_mask, val);
	CASE_GPSI_CHANGE_SW_GCSR(csr, csrid, LOONGARCH_CSR_UCAWIN3_LO, csr_mask, val);
	CASE_GPSI_CHANGE_SW_GCSR(csr, csrid, LOONGARCH_CSR_UCAWIN3_HI, csr_mask, val);

	CASE_GPSI_CHANGE_SW_GCSR(csr, csrid, LOONGARCH_CSR_ERRCTL, csr_mask, val);
	CASE_GPSI_CHANGE_SW_GCSR(csr, csrid, LOONGARCH_CSR_ERRINFO1, csr_mask, val);
	CASE_GPSI_CHANGE_SW_GCSR(csr, csrid, LOONGARCH_CSR_ERRINFO2, csr_mask, val);
	CASE_GPSI_CHANGE_SW_GCSR(csr, csrid, LOONGARCH_CSR_MERRENTRY, csr_mask, val);
	CASE_GPSI_CHANGE_SW_GCSR(csr, csrid, LOONGARCH_CSR_MERRERA, csr_mask, val);
	CASE_GPSI_CHANGE_SW_GCSR(csr, csrid, LOONGARCH_CSR_ERRSAVE, csr_mask, val);

	if (csrid < 4096) {
		unsigned long orig;

		orig = kvm_read_sw_gcsr(csr, csrid);
		orig &= ~csr_mask;
		orig |= val & csr_mask;
		kvm_write_sw_gcsr(csr, csrid, orig);
	}
	kvm_info("Unsupport csr %x exchange @ %lx\n",
				csrid, vcpu->arch.pc);
}

int lvz_getcsr(struct kvm_vcpu *vcpu, unsigned int id, u64 *v, int force)
{
	struct loongarch_csrs *csr = vcpu->arch.csr;

	GET_HW_GCSR(id, LOONGARCH_CSR_CRMD, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_PRMD, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_EUEN, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_MISC, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_ECFG, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_ESTAT, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_ERA, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_BADV, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_BADI, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_EENTRY, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_TLBIDX, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_TLBEHI, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_TLBELO0, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_TLBELO1, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_ASID, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_PGDL, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_PGDH, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_PWCTL0, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_PWCTL1, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_STLBPGSIZE, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_RVACFG, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_CPUID, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_PRCFG1, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_PRCFG2, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_PRCFG3, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_KS0, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_KS1, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_KS2, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_KS3, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_KS4, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_KS5, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_KS6, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_KS7, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_TMID, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_TCFG, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_TVAL, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_CNTC, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_LLBCTL, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_TLBRENTRY, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_TLBRBADV, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_TLBRERA, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_TLBRSAVE, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_TLBRELO0, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_TLBRELO1, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_TLBREHI, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_TLBRPRMD, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_DMWIN0, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_DMWIN1, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_DMWIN2, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_DMWIN3, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_MWPS, v);
	GET_HW_GCSR(id, LOONGARCH_CSR_FWPS, v);

	GET_SW_GCSR(csr, id, LOONGARCH_CSR_IMPCTL1, v);
	GET_SW_GCSR(csr, id, LOONGARCH_CSR_IMPCTL2, v);
	GET_SW_GCSR(csr, id, LOONGARCH_CSR_ERRCTL, v);
	GET_SW_GCSR(csr, id, LOONGARCH_CSR_ERRINFO1, v);
	GET_SW_GCSR(csr, id, LOONGARCH_CSR_ERRINFO2, v);
	GET_SW_GCSR(csr, id, LOONGARCH_CSR_MERRENTRY, v);
	GET_SW_GCSR(csr, id, LOONGARCH_CSR_MERRERA, v);
	GET_SW_GCSR(csr, id, LOONGARCH_CSR_ERRSAVE, v);
	GET_SW_GCSR(csr, id, LOONGARCH_CSR_CTAG, v);
	GET_SW_GCSR(csr, id, LOONGARCH_CSR_MCSR0, v);
	GET_SW_GCSR(csr, id, LOONGARCH_CSR_MCSR1, v);
	GET_SW_GCSR(csr, id, LOONGARCH_CSR_MCSR2, v);
	GET_SW_GCSR(csr, id, LOONGARCH_CSR_MCSR3, v);
	GET_SW_GCSR(csr, id, LOONGARCH_CSR_MCSR8, v);
	GET_SW_GCSR(csr, id, LOONGARCH_CSR_MCSR9, v);
	GET_SW_GCSR(csr, id, LOONGARCH_CSR_MCSR10, v);
	GET_SW_GCSR(csr, id, LOONGARCH_CSR_MCSR24, v);
	GET_SW_GCSR(csr, id, LOONGARCH_CSR_DEBUG, v);
	GET_SW_GCSR(csr, id, LOONGARCH_CSR_DERA, v);
	GET_SW_GCSR(csr, id, LOONGARCH_CSR_DESAVE, v);

	GET_SW_GCSR(csr, id, LOONGARCH_CSR_TINTCLR, v);
	GET_SW_GCSR(csr, id, LOONGARCH_CSR_UCAWIN, v);
	GET_SW_GCSR(csr, id, LOONGARCH_CSR_UCAWIN0_LO, v);
	GET_SW_GCSR(csr, id, LOONGARCH_CSR_UCAWIN0_HI, v);
	GET_SW_GCSR(csr, id, LOONGARCH_CSR_UCAWIN1_LO, v);
	GET_SW_GCSR(csr, id, LOONGARCH_CSR_UCAWIN1_HI, v);
	GET_SW_GCSR(csr, id, LOONGARCH_CSR_UCAWIN2_LO, v);
	GET_SW_GCSR(csr, id, LOONGARCH_CSR_UCAWIN2_HI, v);
	GET_SW_GCSR(csr, id, LOONGARCH_CSR_UCAWIN3_LO, v);
	GET_SW_GCSR(csr, id, LOONGARCH_CSR_UCAWIN3_HI, v);

	if (force && (id < CSR_ALL_SIZE)) {
		*v = kvm_read_sw_gcsr(csr, id);
		return 0;
	}

	return -1;
}

int lvz_setcsr(struct kvm_vcpu *vcpu, unsigned int id, u64 *v, int force)
{
	struct loongarch_csrs *csr = vcpu->arch.csr;
	int ret;

	SET_HW_GCSR(csr, id, LOONGARCH_CSR_CRMD, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_PRMD, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_EUEN, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_MISC, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_ECFG, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_ERA, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_BADV, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_BADI, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_EENTRY, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_TLBIDX, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_TLBEHI, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_TLBELO0, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_TLBELO1, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_ASID, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_PGDL, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_PGDH, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_PWCTL0, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_PWCTL1, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_STLBPGSIZE, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_RVACFG, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_CPUID, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_KS0, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_KS1, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_KS2, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_KS3, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_KS4, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_KS5, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_KS6, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_KS7, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_TMID, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_TCFG, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_TVAL, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_CNTC, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_LLBCTL, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_TLBRENTRY, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_TLBRBADV, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_TLBRERA, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_TLBRSAVE, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_TLBRELO0, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_TLBRELO1, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_TLBREHI, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_TLBRPRMD, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_DMWIN0, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_DMWIN1, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_DMWIN2, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_DMWIN3, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_MWPS, v);
	SET_HW_GCSR(csr, id, LOONGARCH_CSR_FWPS, v);

	SET_SW_GCSR(csr, id, LOONGARCH_CSR_IMPCTL1, v);
	SET_SW_GCSR(csr, id, LOONGARCH_CSR_IMPCTL2, v);
	SET_SW_GCSR(csr, id, LOONGARCH_CSR_ERRCTL, v);
	SET_SW_GCSR(csr, id, LOONGARCH_CSR_ERRINFO1, v);
	SET_SW_GCSR(csr, id, LOONGARCH_CSR_ERRINFO2, v);
	SET_SW_GCSR(csr, id, LOONGARCH_CSR_MERRENTRY, v);
	SET_SW_GCSR(csr, id, LOONGARCH_CSR_MERRERA, v);
	SET_SW_GCSR(csr, id, LOONGARCH_CSR_ERRSAVE, v);
	SET_SW_GCSR(csr, id, LOONGARCH_CSR_CTAG, v);
	SET_SW_GCSR(csr, id, LOONGARCH_CSR_DEBUG, v);
	SET_SW_GCSR(csr, id, LOONGARCH_CSR_DERA, v);
	SET_SW_GCSR(csr, id, LOONGARCH_CSR_DESAVE, v);
	SET_SW_GCSR(csr, id, LOONGARCH_CSR_MCSR0, v);
	SET_SW_GCSR(csr, id, LOONGARCH_CSR_MCSR1, v);
	SET_SW_GCSR(csr, id, LOONGARCH_CSR_MCSR2, v);
	SET_SW_GCSR(csr, id, LOONGARCH_CSR_MCSR3, v);
	SET_SW_GCSR(csr, id, LOONGARCH_CSR_MCSR8, v);
	SET_SW_GCSR(csr, id, LOONGARCH_CSR_MCSR9, v);
	SET_SW_GCSR(csr, id, LOONGARCH_CSR_MCSR10, v);
	SET_SW_GCSR(csr, id, LOONGARCH_CSR_MCSR24, v);
	SET_SW_GCSR(csr, id, LOONGARCH_CSR_PRCFG1, v);
	SET_SW_GCSR(csr, id, LOONGARCH_CSR_PRCFG2, v);
	SET_SW_GCSR(csr, id, LOONGARCH_CSR_PRCFG3, v);

	SET_SW_GCSR(csr, id, LOONGARCH_CSR_PGD, v);
	SET_SW_GCSR(csr, id, LOONGARCH_CSR_TINTCLR, v);
	SET_SW_GCSR(csr, id, LOONGARCH_CSR_UCAWIN, v);
	SET_SW_GCSR(csr, id, LOONGARCH_CSR_UCAWIN0_LO, v);
	SET_SW_GCSR(csr, id, LOONGARCH_CSR_UCAWIN0_HI, v);
	SET_SW_GCSR(csr, id, LOONGARCH_CSR_UCAWIN1_LO, v);
	SET_SW_GCSR(csr, id, LOONGARCH_CSR_UCAWIN1_HI, v);
	SET_SW_GCSR(csr, id, LOONGARCH_CSR_UCAWIN2_LO, v);
	SET_SW_GCSR(csr, id, LOONGARCH_CSR_UCAWIN2_HI, v);
	SET_SW_GCSR(csr, id, LOONGARCH_CSR_UCAWIN3_LO, v);
	SET_SW_GCSR(csr, id, LOONGARCH_CSR_UCAWIN3_HI, v);

	ret = -1;
	switch (id) {
	case LOONGARCH_CSR_ESTAT:
		write_gcsr_estat(*v);
		/* estat IP0~IP7 inject through guestexcept */
		write_csr_gintc(((*v) >> 2)  & 0xff);
		ret = 0;
		break;
	default:
		if (force && (id < CSR_ALL_SIZE)) {
			kvm_set_sw_gcsr(csr, id, *v);
			ret = 0;
		}
		break;
	}

	return ret;
}

struct kvm_iocsr {
	u32 start, end;
	int (*get) (struct kvm_run *run, struct kvm_vcpu *vcpu, u32 addr, u64 *res);
	int (*set) (struct kvm_run *run, struct kvm_vcpu *vcpu, u32 addr, u64 val);
};

static int kvm_iocsr_common_get(struct kvm_run *run, struct kvm_vcpu *vcpu,
		u32 addr, u64 *res)
{
	int r = EMULATE_FAIL;
	struct kvm_iocsr_entry *entry;

	spin_lock(&vcpu->kvm->arch.iocsr_lock);
	entry = kvm_find_iocsr(vcpu->kvm, addr);
	if (entry) {
		r = EMULATE_DONE;
		*res = entry->data;
	}
	spin_unlock(&vcpu->kvm->arch.iocsr_lock);
	return r;
}

static int kvm_iocsr_common_set(struct kvm_run *run, struct kvm_vcpu *vcpu,
		u32 addr, u64 val)
{
	int r = EMULATE_FAIL;
	struct kvm_iocsr_entry *entry;

	spin_lock(&vcpu->kvm->arch.iocsr_lock);
	entry = kvm_find_iocsr(vcpu->kvm, addr);
	if (entry) {
		r = EMULATE_DONE;
		entry->data = val;
	}
	spin_unlock(&vcpu->kvm->arch.iocsr_lock);
	return r;
}

static int kvm_misc_set(struct kvm_run *run, struct kvm_vcpu *vcpu, u32 addr,
		u64 val)
{
	if ((val & IOCSR_MISC_FUNC_EXT_IOI_EN) && vcpu->vcpu_id == 0)
		kvm_setup_ls3a_extirq(vcpu->kvm);
	return kvm_iocsr_common_set(run, vcpu, addr, val);
}

static int kvm_ipi_get(struct kvm_run *run, struct kvm_vcpu *vcpu, u32 addr,
		u64 *res)
{
	int ret;

	++vcpu->stat.lvz_rdcsr_ipi_access_exits;
	run->mmio.phys_addr = KVM_IPI_REG_ADDRESS(vcpu->vcpu_id, (addr & 0xff));
	ret = kvm_io_bus_read(vcpu, KVM_MMIO_BUS, run->mmio.phys_addr,
			run->mmio.len, res);
	if (ret) {
		run->mmio.is_write = 0;
		vcpu->mmio_needed = 1;
		vcpu->mmio_is_write = 0;
		return EMULATE_DO_MMIO;
	}
	return EMULATE_DONE;
}

static int kvm_extioi_isr_get(struct kvm_run *run, struct kvm_vcpu *vcpu,
		u32 addr, u64 *res)
{
	int ret;

	run->mmio.phys_addr =  EXTIOI_PERCORE_ADDR(vcpu->vcpu_id, (addr & 0xff));
	ret = kvm_io_bus_read(vcpu, KVM_MMIO_BUS, run->mmio.phys_addr,
			run->mmio.len, res);
	if (ret) {
		run->mmio.is_write = 0;
		vcpu->mmio_needed = 1;
		vcpu->mmio_is_write = 0;
		return EMULATE_FAIL;
	}

	return EMULATE_DONE;
}

static int kvm_ipi_set(struct kvm_run *run, struct kvm_vcpu *vcpu, u32 addr,
		u64 val)
{
	int ret;

	run->mmio.phys_addr = KVM_IPI_REG_ADDRESS(vcpu->vcpu_id, (addr & 0xff));
	ret = kvm_io_bus_write(vcpu, KVM_MMIO_BUS, run->mmio.phys_addr,
			run->mmio.len, &val);
	if (ret < 0) {
		run->mmio.is_write = 1;
		vcpu->mmio_needed = 1;
		vcpu->mmio_is_write = 1;
		return EMULATE_DO_MMIO;
	}

	return EMULATE_DONE;
}

static int kvm_extioi_set(struct kvm_run *run, struct kvm_vcpu *vcpu, u32 addr,
		u64 val)
{
	int ret;

	if ((addr & 0x1f00) == LOONGARCH_IOCSR_EXTIOI_ISR_BASE) {
		run->mmio.phys_addr =  EXTIOI_PERCORE_ADDR(vcpu->vcpu_id, (addr & 0xff));
	} else {
		run->mmio.phys_addr = EXTIOI_ADDR((addr & 0x1fff));
	}

	ret = kvm_io_bus_write(vcpu, KVM_MMIO_BUS, run->mmio.phys_addr,
			run->mmio.len, &val);
	if (ret < 0) {
		memcpy(run->mmio.data, &val, run->mmio.len);
		run->mmio.is_write = 1;
		vcpu->mmio_needed = 1;
		vcpu->mmio_is_write = 1;
		return EMULATE_DO_MMIO;
	}

	return EMULATE_DONE;
}

static int kvm_nop_set(struct kvm_run *run, struct kvm_vcpu *vcpu, u32 addr,
		u64 val)
{
	return EMULATE_DONE;
}

/* we put these iocsrs with access frequency, from high to low */
static struct kvm_iocsr kvm_iocsrs[] = {
	/* extioi iocsr */
	{LOONGARCH_IOCSR_EXTIOI_EN_BASE, LOONGARCH_IOCSR_EXTIOI_EN_BASE + 0x100,
		NULL, kvm_extioi_set},
	{LOONGARCH_IOCSR_EXTIOI_NODEMAP_BASE, LOONGARCH_IOCSR_EXTIOI_NODEMAP_BASE+0x28,
		NULL, kvm_extioi_set},
	{LOONGARCH_IOCSR_EXTIOI_ROUTE_BASE, LOONGARCH_IOCSR_EXTIOI_ROUTE_BASE + 0x100,
		NULL, kvm_extioi_set},
	{LOONGARCH_IOCSR_EXTIOI_ISR_BASE, LOONGARCH_IOCSR_EXTIOI_ISR_BASE + 0x1c,
		kvm_extioi_isr_get, kvm_extioi_set},

	{LOONGARCH_IOCSR_IPI_STATUS, LOONGARCH_IOCSR_IPI_STATUS + 0x40,
		kvm_ipi_get, kvm_ipi_set},
	{LOONGARCH_IOCSR_IPI_SEND, LOONGARCH_IOCSR_IPI_SEND + 0x1,
		NULL, kvm_ipi_set},
	{LOONGARCH_IOCSR_MBUF_SEND, LOONGARCH_IOCSR_MBUF_SEND + 0x1,
		NULL, kvm_ipi_set},

	{LOONGARCH_IOCSR_FEATURES, LOONGARCH_IOCSR_FEATURES + 0x1,
		kvm_iocsr_common_get, kvm_nop_set},
	{LOONGARCH_IOCSR_VENDOR, LOONGARCH_IOCSR_VENDOR + 0x1,
		kvm_iocsr_common_get, kvm_nop_set},
	{LOONGARCH_IOCSR_CPUNAME, LOONGARCH_IOCSR_CPUNAME + 0x1,
		kvm_iocsr_common_get, kvm_nop_set},
	{LOONGARCH_IOCSR_NODECNT, LOONGARCH_IOCSR_NODECNT + 0x1,
		kvm_iocsr_common_get, kvm_nop_set},
	{LOONGARCH_IOCSR_MISC_FUNC, LOONGARCH_IOCSR_MISC_FUNC + 0x1,
		kvm_iocsr_common_get, kvm_misc_set},
};

static int lvz_iocsr_read(struct kvm_run *run, struct kvm_vcpu *vcpu,
		u32 addr, u64 *res)
{
	enum emulation_result er = EMULATE_FAIL;
	int i = 0;
	struct kvm_iocsr *iocsr = NULL;

	for (i = 0; i < sizeof(kvm_iocsrs) / sizeof(struct kvm_iocsr); i++) {
		iocsr = &kvm_iocsrs[i];
		if (addr >= iocsr->start && addr < iocsr->end) {
			if (iocsr->get)
				er = iocsr->get(run, vcpu, addr, res);
		}
	}

	if (er != EMULATE_DONE)
		kvm_debug("%s iocsr 0x%x not support in kvm\n", __func__, addr);

	return er;
}

static int lvz_iocsr_write(struct kvm_run *run, struct kvm_vcpu *vcpu,
		u32 addr, u64 val)
{
	enum emulation_result er = EMULATE_FAIL;
	int i = 0;
	struct kvm_iocsr *iocsr = NULL;

	for (i = 0; i < sizeof(kvm_iocsrs) / sizeof(struct kvm_iocsr); i++) {
		iocsr = &kvm_iocsrs[i];
		if (addr >= iocsr->start && addr < iocsr->end) {
			if (iocsr->set)
				er = iocsr->set(run, vcpu, addr, val);
		}
	}
	if (er != EMULATE_DONE)
		kvm_debug("%s iocsr 0x%x not support in kvm\n", __func__, addr);

	return er;
}

/* all iocsr operation should in kvm, no mmio */
int lvz_gpsi_iocsr(larch_inst inst,
		struct kvm_run *run, struct kvm_vcpu *vcpu)
{
	u32 rd, rj, opcode;
	u32 iocsr_val;
	u64 res = 0;
	int ret;

	/*
	 * Each IOCSR with different opcode
	 */
	rd = inst.reg2_format.rd;
	rj = inst.reg2_format.rj;
	opcode = inst.reg2_format.opcode;
	iocsr_val = vcpu->arch.gprs[rj];
	/* LoongArch is Little endian */
	switch (opcode) {
	case iocsrrdb_op:
		run->mmio.len = 1;
		ret = lvz_iocsr_read(run, vcpu, iocsr_val, &res);
		vcpu->arch.gprs[rd] = (u8) res;
		break;
	case iocsrrdh_op:
		run->mmio.len = 2;
		ret = lvz_iocsr_read(run, vcpu, iocsr_val, &res);
		vcpu->arch.gprs[rd] = (u16) res;
		break;
	case iocsrrdw_op:
		run->mmio.len = 4;
		ret = lvz_iocsr_read(run, vcpu, iocsr_val, &res);
		vcpu->arch.gprs[rd] = (u32) res;
		break;
	case iocsrrdd_op:
		run->mmio.len = 8;
		ret = lvz_iocsr_read(run, vcpu, iocsr_val, &res);
		vcpu->arch.gprs[rd] = res;
		break;
	case iocsrwrb_op:
		run->mmio.len = 1;
		ret = lvz_iocsr_write(run, vcpu, iocsr_val,
				(u8) vcpu->arch.gprs[rd]);
		break;
	case iocsrwrh_op:
		run->mmio.len = 2;
		ret = lvz_iocsr_write(run, vcpu, iocsr_val,
				(u16) vcpu->arch.gprs[rd]);
		break;
	case iocsrwrw_op:
		run->mmio.len = 4;
		ret = lvz_iocsr_write(run, vcpu, iocsr_val,
				(u32) vcpu->arch.gprs[rd]);
		break;
	case iocsrwrd_op:
		run->mmio.len = 8;
		ret = lvz_iocsr_write(run, vcpu, iocsr_val,
				vcpu->arch.gprs[rd]);
		break;
	default:
		ret = EMULATE_FAIL;
		break;
	}

	return ret;
}

int lvz_iocsr_get(struct kvm *kvm, struct kvm_iocsr_entry *__user argp)
{
	struct kvm_iocsr_entry *entry, tmp;
	int r = -EFAULT;

	if (copy_from_user(&tmp, argp, sizeof(tmp)))
		goto out;

	spin_lock(&kvm->arch.iocsr_lock);
	entry = kvm_find_iocsr(kvm, tmp.addr);
	if (entry != NULL)
		tmp.data = entry->data;
	spin_unlock(&kvm->arch.iocsr_lock);

	if (entry)
		r = copy_to_user(argp, &tmp, sizeof(tmp));

out:
	return r;
}

int lvz_iocsr_set(struct kvm *kvm, struct kvm_iocsr_entry *__user argp)
{
	struct kvm_iocsr_entry *entry, tmp;
	int r = -EFAULT;

	if (copy_from_user(&tmp, argp, sizeof(tmp)))
		goto out;

	spin_lock(&kvm->arch.iocsr_lock);
	entry = kvm_find_iocsr(kvm, tmp.addr);
	if (entry != NULL) {
		r = 0;
		entry->data = tmp.data;
	}
	spin_unlock(&kvm->arch.iocsr_lock);

	if (tmp.addr == LOONGARCH_IOCSR_MISC_FUNC)
		kvm_enable_ls3a_extirq(kvm, tmp.data & IOCSR_MISC_FUNC_EXT_IOI_EN);

out:
	return r;
}

struct kvm_iocsr_entry *kvm_find_iocsr(struct kvm *kvm, u32 addr)
{
	int i = 0;

	for (i = 0; i < IOCSR_MAX; i++) {
		if (addr == kvm->arch.iocsr[i].addr)
			return &kvm->arch.iocsr[i];
	}

	return NULL;
}

static struct kvm_iocsr_entry iocsr_array[IOCSR_MAX] = {
	{LOONGARCH_IOCSR_FEATURES, .data = IOCSRF_NODECNT|IOCSRF_MSI
		|IOCSRF_EXTIOI|IOCSRF_CSRIPI|IOCSRF_VM},
	{LOONGARCH_IOCSR_VENDOR, .data = 0x6e6f73676e6f6f4c}, /* Loongson */
	{LOONGARCH_IOCSR_CPUNAME, .data = 0x303030354133},	/* 3A5000 */
	{LOONGARCH_IOCSR_NODECNT, .data = 0x4},
	{LOONGARCH_IOCSR_MISC_FUNC, .data = 0x0},
};

int lvz_iocsr_init(struct kvm *kvm)
{
	int i = 0;

	spin_lock_init(&kvm->arch.iocsr_lock);
	for (i = 0; i < IOCSR_MAX; i++) {
		kvm->arch.iocsr[i].addr = iocsr_array[i].addr;
		kvm->arch.iocsr[i].data = iocsr_array[i].data;
	}
	return 0;
}
