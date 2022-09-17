/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * KVM/LOONGISA TLB handling, this file is part of the Linux host kernel so that
 * TLB handlers run from XKPHYS
 *
 * Copyright (C) 2020 Loongson  Technologies, Inc.  All rights reserved.
 * Authors: Xing Li <lixing@loongson.cn>
 */

#include <linux/sched.h>
#include <linux/smp.h>
#include <linux/mm.h>
#include <linux/delay.h>
#include <linux/export.h>
#include <linux/kvm_host.h>
#include <linux/srcu.h>
#ifdef CONFIG_LOONGARCH_HUGE_TLB_SUPPORT
#include <linux/hugetlb.h>
#endif
#include <asm/cpu.h>
#include <asm/bootinfo.h>
#include <asm/mmu_context.h>
#include <asm/pgtable.h>
#include <asm/cacheflush.h>
#include <asm/tlb.h>

#define KVM_GUEST_PC_TLB    0
#define KVM_GUEST_SP_TLB    1

unsigned long GUESTID_MASK;
EXPORT_SYMBOL_GPL(GUESTID_MASK);
unsigned long GUESTID_FIRST_VERSION;
EXPORT_SYMBOL_GPL(GUESTID_FIRST_VERSION);
unsigned long GUESTID_VERSION_MASK;
EXPORT_SYMBOL_GPL(GUESTID_VERSION_MASK);

static int _kvm_loongarch_host_tlb_update(struct kvm_vcpu *vcpu, unsigned long entryhi)
{
	int idx;
	pgd_t *pgdp;
	pud_t *pudp;
	pmd_t *pmdp;
	pte_t *ptep;

	entryhi &= (PAGE_MASK << 1);
	pgdp = vcpu->kvm->arch.gpa_mm.pgd + pgd_index(entryhi);
	pudp = pud_offset(pgdp, entryhi);
	pmdp = pmd_offset(pudp, entryhi);

	write_csr_entryhi(entryhi);
	tlb_probe();
	idx = read_csr_tlbidx();

#ifdef CONFIG_LOONGARCH_HUGE_TLB_SUPPORT

	/* this could be a huge page  */
	if (pmd_huge(*pmdp)) {
		unsigned long lo;
		write_csr_pagesize(PS_HUGE_SIZE);
		ptep = (pte_t *)pmdp;
		lo = pmd_to_entrylo(pte_val(*ptep));
		write_csr_entrylo0(lo);
		write_csr_entrylo1(lo + (HPAGE_SIZE >> 1));

		if (idx < 0)
			tlb_write_random();
		else
			tlb_write_indexed();
		write_csr_pagesize(PS_DEFAULT_SIZE);
	} else
#endif
	{
		write_csr_pagesize(PS_DEFAULT_SIZE);
		ptep = pte_offset_map(pmdp, entryhi);

		write_csr_entrylo0(pte_to_entrylo(pte_val(*ptep++)));
		write_csr_entrylo1(pte_to_entrylo(pte_val(*ptep)));

		if (idx < 0)
			tlb_write_random();
		else
			tlb_write_indexed();
	}
	return idx;
}

/* GuestID management */

/**
 * clear_root_gid() - Set tlbgst.RID for normal root operation.
 */
static inline void clear_root_gid(void)
{
	clear_csr_gtlbc(CSR_GTLBC_RID);
}

/**
 * set_root_gid_to_guest_gid() - Set gtlbc.RID to match guestinfo.ID.
 *
 * Sets the root GuestID to match the current guest GuestID, for TLB operation
 * on the GPA->RPA mappings in the root TLB.
 *
 * The caller must be sure to disable HTW while the root GID is set, and
 * possibly longer if TLB registers are modified.
 */
static inline void set_root_gid_to_guest_gid(void)
{
	unsigned int guestid;
	unsigned int tlbguest;

	guestid = read_csr_gstat() & CSR_GSTAT_GID;
	tlbguest = read_csr_gtlbc() & (~CSR_GTLBC_RID);
	write_csr_gtlbc(tlbguest | guestid);
}

int kvm_lvz_host_tlb_inv(struct kvm_vcpu *vcpu, unsigned long va)
{
	preempt_disable();
	invtlb(INVTLB_GID_ADDR, read_csr_gstat() & CSR_GSTAT_GID, va & VPPN_MASK);
	preempt_enable();
	return 0;
}
EXPORT_SYMBOL_GPL(kvm_lvz_host_tlb_inv);

int kvm_lvz_host_tlb_update(struct kvm_vcpu *vcpu, unsigned long va)
{
	int idx;
	unsigned long flags, old_entryhi;

	local_irq_save(flags);

	/* Set root GuestID for root probe and write of guest TLB entry */
	set_root_gid_to_guest_gid();

	old_entryhi = read_csr_entryhi();

	idx = _kvm_loongarch_host_tlb_update(vcpu, (va & VPPN_MASK));

	write_csr_entryhi(old_entryhi);
	clear_root_gid();

	local_irq_restore(flags);

	if (idx > 0)
		kvm_debug("%s: Update root entryhi %#lx @ idx %d\n",
			  __func__, (va & VPPN_MASK), idx);

	return 0;
}
EXPORT_SYMBOL_GPL(kvm_lvz_host_tlb_update);

/**
 * kvm_lvz_local_flush_roottlb_all_guests() - Flush all root TLB entries for
 * guests.
 *
 * Invalidate all entries including GVA-->GPA and GPA-->HPA mappings.
 */
void kvm_lvz_local_flush_roottlb_all_guests(void)
{
	unsigned long flags;
	local_irq_save(flags);
	invtlb_all(INVTLB_ALLGID, 0, 0);
	local_irq_restore(flags);
}
EXPORT_SYMBOL_GPL(kvm_lvz_local_flush_roottlb_all_guests);

/**
 * kvm_lvz_local_flush_guesttlb_all() - Flush all guest TLB entries.
 *
 * Invalidate all entries in guest tlb irrespective of guestid.
 */
void kvm_lvz_local_flush_guesttlb_all(void)
{
	unsigned long flags;
	local_irq_save(flags);
	invtlb_all(INVGTLB_ALLGID_GVA_TO_GPA, 0, 0);
	local_irq_restore(flags);
}
EXPORT_SYMBOL_GPL(kvm_lvz_local_flush_guesttlb_all);

void kvm_loongarch_clear_guest_mtlb(void)
{
	unsigned long idx = read_gcsr_tlbidx();
	/* Set root GuestID for root probe and write of guest TLB entry */
	set_root_gid_to_guest_gid();

	change_gcsr_tlbidx(CSR_TLBIDX_IDX, 2048);
	guest_tlbinvf();

	clear_root_gid();

	write_gcsr_tlbidx(idx);
	write_csr_impctl2(CSR_FLUSH_ITLB | CSR_FLUSH_DTLB);
}
EXPORT_SYMBOL_GPL(kvm_loongarch_clear_guest_mtlb);

void kvm_loongarch_clear_guest_stlb(void)
{
	int i;
	unsigned long idx = read_gcsr_tlbidx();
	/* Set root GuestID for root probe and write of guest TLB entry */
	set_root_gid_to_guest_gid();

	for (i = 0;
	     i < current_cpu_data.tlbsizestlbsets;
	     i++) {
		change_gcsr_tlbidx(CSR_TLBIDX_IDX, i);
		guest_tlbinvf();
	}
	clear_root_gid();

	write_gcsr_tlbidx(idx);
	write_csr_impctl2(CSR_FLUSH_ITLB | CSR_FLUSH_DTLB);
}
EXPORT_SYMBOL_GPL(kvm_loongarch_clear_guest_stlb);
