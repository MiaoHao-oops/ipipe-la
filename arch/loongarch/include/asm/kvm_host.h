/* SPDX-License-Identifier: GPL-2.0 */
/*
* This file is subject to the terms and conditions of the GNU General Public
* License.  See the file "COPYING" in the main directory of this archive
* for more details.
*
* Copyright (C) 2020 Loongson Technologies, Inc.  All rights reserved.
* Authors: Xing Li <lixing@loongson.cn>
*/

#ifndef __LOONGARCH_KVM_HOST_H__
#define __LOONGARCH_KVM_HOST_H__

#include <linux/cpumask.h>
#include <linux/mutex.h>
#include <linux/hrtimer.h>
#include <linux/interrupt.h>
#include <linux/types.h>
#include <linux/kvm.h>
#include <linux/kvm_types.h>
#include <linux/threads.h>
#include <linux/spinlock.h>

#include <asm/inst.h>
#include <asm/loongarchregs.h>
#include <asm/compiler.h>

/* Loongarch KVM register ids */
#define LOONGARCH_CSR_32(_R, _S)					\
	(KVM_REG_LOONGARCH_CSR | KVM_REG_SIZE_U32 | (8 * (_R) + (_S)))

#define LOONGARCH_CSR_64(_R, _S)					\
	(KVM_REG_LOONGARCH_CSR | KVM_REG_SIZE_U64 | (8 * (_R) + (_S)))

#define KVM_IOC_CSRID(id)	LOONGARCH_CSR_64(id, 0)
#define KVM_GET_IOC_CSRIDX(id)	((id & KVM_CSR_IDX_MASK) >> 3)

#define LOONGSON_VIRT_REG_BASE	0x1f000000
#define KVM_MAX_VCPUS		256
#define KVM_USER_MEM_SLOTS	256
/* memory slots that does not exposed to userspace */
#define KVM_PRIVATE_MEM_SLOTS	0

#define KVM_HALT_POLL_NS_DEFAULT 500000

#define KVM_REQ_RECORD_STEAL	KVM_ARCH_REQ(1)

extern unsigned long GUESTID_MASK;
extern unsigned long GUESTID_FIRST_VERSION;
extern unsigned long GUESTID_VERSION_MASK;

typedef union loongarch_instruction  larch_inst;
typedef int (*exit_handle_fn)(struct kvm_vcpu *);

#define KVM_INVALID_ADDR		0xdeadbeef
#define KVM_HVA_ERR_BAD			(-1UL)
#define KVM_HVA_ERR_RO_BAD		(-2UL)
static inline bool kvm_is_error_hva(unsigned long addr)
{
	return IS_ERR_VALUE(addr);
}

struct kvm_vm_stat {
	ulong remote_tlb_flush;
	u64 lvz_kvm_vm_ioctl_irq_line;
	u64 lvz_kvm_ls7a_ioapic_update;
	u64 lvz_kvm_ls7a_ioapic_set_irq;
	u64 lvz_ls7a_ioapic_reg_write;
	u64 lvz_ls7a_ioapic_reg_read;
	u64 lvz_kvm_set_ls7a_ioapic;
	u64 lvz_kvm_get_ls7a_ioapic;
	u64 lvz_kvm_set_ls3a_ext_irq;
	u64 lvz_kvm_get_ls3a_ext_irq;
	u64 lvz_kvm_trigger_ls3a_ext_irq;
	u64 lvz_kvm_pip_read_exits;
	u64 lvz_kvm_pip_write_exits;
	u64 lvz_kvm_ls7a_msi_irq;
};
struct kvm_vcpu_stat {
	u64 excep_exits[EXCCODE_INT_START];
	u64 wait_exits;
	u64 signal_exits;
	u64 int_exits;
	u64 lvz_rdcsr_cpu_feature_exits;
	u64 lvz_rdcsr_misc_func_exits;
	u64 lvz_rdcsr_ipi_access_exits;
	u64 lvz_cpucfg_exits;
	u64 lvz_huge_dec_exits;
	u64 lvz_huge_thp_exits;
	u64 lvz_huge_adjust_exits;
	u64 lvz_huge_set_exits;
	u64 lvz_huge_merge_exits;
	u64 halt_successful_poll;
	u64 halt_attempted_poll;
	u64 halt_poll_invalid;
	u64 halt_wakeup;
};

struct kvm_arch_memory_slot {
};

enum {
	IOCSR_FEATURES,
	IOCSR_VENDOR,
	IOCSR_CPUNAME,
	IOCSR_NODECNT,
	IOCSR_MISC_FUNC,
	IOCSR_MAX
};

struct kvm_ops;
struct kvm_arch {
	/* Guest physical mm */
	struct mm_struct gpa_mm;
	/* Mask of CPUs needing GPA ASID flush */
	cpumask_t asid_flush_mask;

	unsigned char online_vcpus;
	unsigned char is_migrate;
	s64 stablecounter_gftoffset;
	u32 cpucfg_lasx;
	/* Check hypcall work or not */
	u32 hypcall_check;
	struct ls7a_kvm_ioapic *v_ioapic;
	struct ls3a_kvm_ipi *v_gipi;
	struct ls3a_kvm_routerirq *v_routerirq;
	struct ls3a_kvm_extirq *v_extirq;
	spinlock_t iocsr_lock;
	struct kvm_iocsr_entry iocsr[IOCSR_MAX];
	struct kvm_cpucfg cpucfgs;
	struct kvm_ops *kvm_ops;
};


#define LOONGARCH_CSRS	0x100
#define CSR_UCWIN_BASE	0x100
#define CSR_UCWIN_SIZE	0x10
#define CSR_DMWIN_BASE	0x180
#define CSR_DMWIN_SIZE	0x4
#define CSR_PERF_BASE	0x200
#define CSR_PERF_SIZE	0x8
#define CSR_DEBUG_BASE	0x500
#define CSR_DEBUG_SIZE	0x3
#define CSR_ALL_SIZE	0x800

struct loongarch_csrs {
	unsigned long csrs[CSR_ALL_SIZE];
};

/* Resume Flags */
#define RESUME_FLAG_DR		(1<<0)	/* Reload guest nonvolatile state? */
#define RESUME_FLAG_HOST	(1<<1)	/* Resume host? */

#define RESUME_GUEST		0
#define RESUME_GUEST_DR		RESUME_FLAG_DR
#define RESUME_HOST		RESUME_FLAG_HOST

enum emulation_result {
	EMULATE_DONE,		/* no further processing */
	EMULATE_DO_MMIO,	/* kvm_run filled with MMIO request */
	EMULATE_FAIL,		/* can't emulate this instruction */
	EMULATE_WAIT,		/* WAIT instruction */
	EMULATE_PRIV_FAIL,
	EMULATE_EXCEPT,		/* A guest exception has been generated */
	EMULATE_HYPERCALL,	/* HYPCALL instruction */
	EMULATE_DEBUG,		/* Emulate guest kernel debug */
};

#define loongarch3_paddr_to_tlbpfn(x) \
	(((unsigned long)(x) >> LOONGARCH3_PG_SHIFT) & LOONGARCH3_PG_FRAME)
#define loongarch3_tlbpfn_to_paddr(x) \
	((unsigned long)((x) & LOONGARCH3_PG_FRAME) << LOONGARCH3_PG_SHIFT)

#define LOONGARCH3_PG_SHIFT		6
#define LOONGARCH3_PG_FRAME		0x3fffffc0

#define VPPN_MASK		GENMASK(cpu_vabits - 1, 12)
#define KVM_ENTRYHI_ASID	cpu_asid_mask(&current_cpu_data)
#define TLB_IS_GLOBAL(x)	((x).tlb_lo[0] & (x).tlb_lo[1] & ENTRYLO_G)
#define TLB_VPPN(x)		((x).tlb_hi & VPPN_MASK)
#define TLB_ASID(x)		((x).tlb_hi & KVM_ENTRYHI_ASID)
#define TLB_LO_IDX(x, va)	(((va) >> PAGE_SHIFT) & 1)
#define TLB_IS_VALID(x, va)	((x).tlb_lo[TLB_LO_IDX(x, va)] & ENTRYLO_V)
#define TLB_IS_DIRTY(x, va)	((x).tlb_lo[TLB_LO_IDX(x, va)] & ENTRYLO_D)
#define TLB_HI_ASID_HIT(x, y)	(TLB_IS_GLOBAL(x) ||			\
				 TLB_ASID(x) == ((y) & KVM_ENTRYHI_ASID))

struct kvm_loongarch_tlb {
	long tlb_asid;
	long tlb_idx;
	long tlb_hi;
	long tlb_lo[2];
};

#define KVM_NR_MEM_OBJS     4

/*
 * We don't want allocation failures within the mmu code, so we preallocate
 * enough memory for a single page fault in a cache.
 */
struct kvm_mmu_memory_cache {
	int nobjs;
	void *objects[KVM_NR_MEM_OBJS];
};

#if defined(CONFIG_CPU_HAS_LASX)
#define FPU_ALIGN		__aligned(32)
#elif defined(CONFIG_CPU_HAS_LSX)
#define FPU_ALIGN		__aligned(16)
#else
#define FPU_ALIGN
#endif
#define KVM_LARCH_FPU		(0x1 << 0)
#define KVM_LARCH_LSX		(0x1 << 1)
#define KVM_LARCH_LASX		(0x1 << 2)
#define KVM_LARCH_DATA_HWBP	(0x1 << 3)
#define KVM_LARCH_INST_HWBP	(0x1 << 4)
#define KVM_LARCH_HWBP		(KVM_LARCH_DATA_HWBP | KVM_LARCH_INST_HWBP)
#define KVM_LARCH_RESET		(0x1 << 5)
#define KVM_LARCH_PERF		(0x1 << 6)

struct kvm_vcpu_arch {
	unsigned long guest_eentry;
	unsigned long host_eentry;
	int (*vcpu_run)(struct kvm_run *run, struct kvm_vcpu *vcpu);
	int (*handle_exit)(struct kvm_run *run, struct kvm_vcpu *vcpu);

	/* Host registers preserved across guest mode execution */
	unsigned long host_stack;
	unsigned long host_gp;
	unsigned long host_pgd;
	unsigned long host_pgdhi;
	unsigned long host_entryhi;

	/* Host CSR registers used when handling exits from guest */
	unsigned long host_badvaddr;
	unsigned long host_era;
	unsigned long host_gtlbc;
	unsigned long host_estat;
	unsigned long host_crmd;
	unsigned long host_prmd;
	unsigned long host_badinstr;
	unsigned long host_gstat;
	unsigned long host_gcfg;
	unsigned long host_ecfg;
	unsigned long host_percpu;

	u32 is_hypcall;
	/* GPRS */
	unsigned long gprs[32];
	unsigned long pc;

	/* FPU State */
	struct loongarch_fpu fpu FPU_ALIGN;
	/* Which auxiliary state is loaded (KVM_LOONGARCH_AUX_*) */
	unsigned int aux_inuse;

	/* CSR State */
	struct loongarch_csrs *csr;

	/* Resume PC after MMIO completion */
	unsigned long io_pc;
	/* GPR used as IO source/target */
	u32 io_gpr;

	struct hrtimer swtimer;
	/* Count timer control KVM register */
	u32 count_ctl;

	/* Bitmask of exceptions that are pending */
	unsigned long pending_exceptions;

	/* Bitmask of pending exceptions to be cleared */
	unsigned long pending_exceptions_clr;

	/* Guest kernel/user [partial] mm */
	struct mm_struct guest_kernel_mm, guest_user_mm;

	/* Guest ASID of last user mode execution */
	unsigned int last_user_gasid;

	/* Cache some mmu pages needed inside spinlock regions */
	struct kvm_mmu_memory_cache mmu_page_cache;

	/* vcpu's vzguestid is different on each host cpu in an smp system */
	u64 vzguestid[NR_CPUS];

	/* Period of stable timer tick in ns */
	u64 timer_period;
	/* Frequency of stable timer in Hz */
	u64 timer_mhz;
	/* Stable bias from the raw time */
	u64 timer_bias;
	/* Dynamic nanosecond bias (multiple of timer_period) to avoid overflow */
	s64 timer_dyn_bias;
	/* Save ktime */
	ktime_t stable_ktime_saved;

	u64 core_ext_ioisr[4];

	/* Last CPU the VCPU state was loaded on */
	int last_sched_cpu;
	/* Last CPU the VCPU actually executed guest code on */
	int last_exec_cpu;

	/* WAIT executed */
	int wait;

	u8 fpu_enabled;
	u8 lsx_enabled;
	/* paravirt steal time */
	struct {
		u64 guest_addr;
		u64 last_steal;
		struct gfn_to_pfn_cache cache;
	} st;
	struct kvm_guest_debug_arch guest_debug;
	/* save host pmu csr */
	u64 perf_ctrl[4];
	u64 perf_cntr[4];

};

static inline unsigned long readl_sw_gcsr(struct loongarch_csrs *csr, int reg)
{
	return csr->csrs[reg];
}

static inline void writel_sw_gcsr(struct loongarch_csrs *csr, int reg, \
		unsigned long val)
{
	csr->csrs[reg] = val;
}

/* Helpers */

static inline bool kvm_loongarch_guest_can_have_fpu(struct kvm_vcpu_arch *arch)
{
	return (!__builtin_constant_p(cpu_has_fpu) || cpu_has_fpu) &&
		arch->fpu_enabled;
}

static inline bool kvm_loongarch_guest_has_fpu(struct kvm_vcpu_arch *arch)
{
	return kvm_loongarch_guest_can_have_fpu(arch);
}

static inline bool kvm_loongarch_guest_can_have_lsx(struct kvm_vcpu_arch *arch)
{
	return (!__builtin_constant_p(cpu_has_lsx) || cpu_has_lsx) &&
		arch->lsx_enabled;
}

static inline bool kvm_loongarch_guest_has_lsx(struct kvm_vcpu_arch *arch)
{
	return kvm_loongarch_guest_can_have_lsx(arch);
}

bool kvm_loongarch_guest_has_lasx(struct kvm_vcpu *vcpu);

struct kvm_ops {
	int (*vcpu_init)(struct kvm_vcpu *vcpu);
	void (*vcpu_uninit)(struct kvm_vcpu *vcpu);
	int (*vcpu_setup)(struct kvm_vcpu *vcpu);
	void (*flush_shadow_all)(struct kvm *kvm);
	/*
	 * Must take care of flushing any cached GPA PTEs (e.g. guest entries in
	 * VZ root TLB, or T&E GVA page tables and corresponding root TLB
	 * mappings).
	 */
	void (*flush_shadow_memslot)(struct kvm *kvm,
				     const struct kvm_memory_slot *slot);
	gpa_t (*gva_to_gpa)(gva_t gva);
	void (*queue_timer_int)(struct kvm_vcpu *vcpu);
	void (*dequeue_timer_int)(struct kvm_vcpu *vcpu);
	void (*queue_io_int)(struct kvm_vcpu *vcpu, int intr);
	void (*dequeue_io_int)(struct kvm_vcpu *vcpu, int intr);
	int (*irq_deliver)(struct kvm_vcpu *vcpu, unsigned int priority);
	int (*irq_clear)(struct kvm_vcpu *vcpu, unsigned int priority);
	unsigned long (*num_regs)(struct kvm_vcpu *vcpu);
	int (*copy_reg_indices)(struct kvm_vcpu *vcpu, u64 __user *indices);
	int (*get_one_reg)(struct kvm_vcpu *vcpu,
			   const struct kvm_one_reg *reg, s64 *v);
	int (*set_one_reg)(struct kvm_vcpu *vcpu,
			   const struct kvm_one_reg *reg, s64 v);
	int (*vcpu_load)(struct kvm_vcpu *vcpu, int cpu);
	int (*vcpu_put)(struct kvm_vcpu *vcpu, int cpu);
	int (*vcpu_run)(struct kvm_run *run, struct kvm_vcpu *vcpu);
	void (*vcpu_reenter)(struct kvm_run *run, struct kvm_vcpu *vcpu);
};
int kvm_lvz_ops_init(struct kvm *kvm);

/* Debug: dump vcpu state */
int kvm_arch_vcpu_dump_regs(struct kvm_vcpu *vcpu);

extern int kvm_loongarch_handle_exit(struct kvm_run *run, struct kvm_vcpu *vcpu);

/* Building of entry/exception code */
int kvm_loongarch_scratch_setup(void);
void *kvm_loongarch_build_vcpu_run(void *addr);
void *kvm_loongarch_build_tlb_refill_exception(void *addr, void *handler);
void *kvm_loongarch_build_exception(void *addr, void *handler);
void *kvm_loongarch_build_exit(void *addr);

/* TLB handlings */
int kvm_loongarch_handle_lvz_root_tlb_fault(unsigned long badvaddr,
				      struct kvm_vcpu *vcpu, bool write_fault);
int kvm_lvz_host_tlb_inv(struct kvm_vcpu *vcpu, unsigned long entryhi);
int kvm_lvz_host_tlb_update(struct kvm_vcpu *vcpu, unsigned long entryhi);
int kvm_lvz_guest_tlb_lookup(struct kvm_vcpu *vcpu, unsigned long gva,
			    unsigned long *gpa);
void kvm_lvz_local_flush_roottlb_all_guests(void);
void kvm_lvz_local_flush_guesttlb_all(void);
void kvm_lvz_save_guesttlb(struct kvm_loongarch_tlb *buf, unsigned int index,
			  unsigned int count);
void kvm_lvz_load_guesttlb(const struct kvm_loongarch_tlb *buf, unsigned int index,
			  unsigned int count);
void kvm_loongarch_clear_guest_mtlb(void);
void kvm_loongarch_clear_guest_stlb(void);

/* MMU handling */

void kvm_loongarch_destroy_mm(struct kvm *kvm);
pgd_t *kvm_pgd_alloc(void);
void kvm_mmu_free_memory_caches(struct kvm_vcpu *vcpu);

enum kvm_loongarch_fault_result {
	KVM_LOONGARCH_MAPPED = 0,
	KVM_LOONGARCH_GVA,
	KVM_LOONGARCH_GPA,
	KVM_LOONGARCH_TLB,
	KVM_LOONGARCH_TLBINV,
	KVM_LOONGARCH_TLBMOD,
};
enum kvm_loongarch_fault_result kvm_trap_emul_gva_fault(struct kvm_vcpu *vcpu,
						   unsigned long gva,
						   bool write);
#define KVM_ARCH_WANT_MMU_NOTIFIER
int kvm_unmap_hva_range(struct kvm *kvm,
			unsigned long start, unsigned long end, bool blockable);
void kvm_set_spte_hva(struct kvm *kvm, unsigned long hva, pte_t pte);
int kvm_age_hva(struct kvm *kvm, unsigned long start, unsigned long end);
int kvm_test_age_hva(struct kvm *kvm, unsigned long hva);

static inline void kvm_get_badinstr(struct kvm_vcpu_arch *arch, unsigned int *out)
{
	*out = arch->host_badinstr;
}

static inline void update_pc(struct kvm_vcpu_arch *arch)
{
	arch->pc += 4;
}

/**
 * kvm_is_ifetch_fault() - Find whether a TLBL exception is due to ifetch fault.
 * @vcpu:	Virtual CPU.
 *
 * Returns:	Whether the TLBL exception was likely due to an instruction
 *		fetch fault rather than a data load fault.
 */
static inline bool kvm_is_ifetch_fault(struct kvm_vcpu_arch *arch)
{
	if (arch->pc == arch->host_badvaddr)
		return true;

	return false;
}

int kvm_larch_emu_st(larch_inst inst, struct kvm_vcpu *vcpu);
int kvm_larch_emu_ld(larch_inst inst, struct kvm_vcpu *vcpu);
int kvm_larch_complete_ld(struct kvm_vcpu *vcpu, struct kvm_run *run);
int kvm_loongarch_emul_wait(struct kvm_vcpu *vcpu);
int kvm_loongarch_emul_hypcall(struct kvm_vcpu *vcpu, larch_inst inst);
int kvm_loongarch_handle_hypcall(struct kvm_vcpu *vcpu);

/* Misc */
extern unsigned long kvm_loongarch_get_ramsize(struct kvm *kvm);

static inline void kvm_arch_hardware_unsetup(void) {}
static inline void kvm_arch_sync_events(struct kvm *kvm) {}
static inline void kvm_arch_free_memslot(struct kvm *kvm,
		struct kvm_memory_slot *free, struct kvm_memory_slot *dont) {}
static inline void kvm_arch_memslots_updated(struct kvm *kvm, u64 gen) {}
static inline void kvm_arch_sched_in(struct kvm_vcpu *vcpu, int cpu) {}
static inline void kvm_arch_vcpu_blocking(struct kvm_vcpu *vcpu) {}
static inline void kvm_arch_vcpu_unblocking(struct kvm_vcpu *vcpu) {}
static inline void kvm_arch_vcpu_block_finish(struct kvm_vcpu *vcpu) {}

extern int kvm_enter_guest(struct kvm_run *run, struct kvm_vcpu *vcpu);
extern void kvm_exception_entry(void);
extern void do_vi(int irq);
#endif /* __LOONGARCH_KVM_HOST_H__ */
