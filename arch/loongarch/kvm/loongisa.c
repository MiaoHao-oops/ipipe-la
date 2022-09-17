/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * KVM/LOONGISA: LOONGISA specific KVM APIs
 *
 * Copyright (C) 2020 Loongson  Technologies, Inc.  All rights reserved.
 * Authors: Xing Li <lixing@loongson.cn>
 */

#include <linux/bitops.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/kdebug.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/sched/signal.h>
#include <linux/fs.h>
#include <linux/bootmem.h>
#include <linux/mod_devicetable.h>
#include <linux/kvm.h>
#include <linux/debugfs.h>
#include <linux/pid.h>

#include <asm/fpu.h>
#include <asm/watch.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/cpufeature.h>

#include <linux/kvm_host.h>

#include "interrupt.h"
#include "ls3a.h"
#include "hw_breakpoint.h"
#include <asm/loongarchregs.h>
#include <asm/setup.h>
#include <asm/paravirt.h>

/*
 * Define loongarch kvm version.
 * Add version number when qemu/kvm interface changed
 */
#define KVM_LOONGARCH_VERSION 1
#define CREATE_TRACE_POINTS
#include "trace.h"
#define VCPU_STAT(x) offsetof(struct kvm_vcpu, stat.x)
#define VM_STAT(x) offsetof(struct kvm, stat.x)
struct kvm_stats_debugfs_item vcpu_debugfs_entries[] = {
	{ "wait",	  VCPU_STAT(wait_exits),	 KVM_STAT_VCPU },
	{ "signal",	  VCPU_STAT(signal_exits),	 KVM_STAT_VCPU },
	{ "interrupt",	  VCPU_STAT(int_exits),		 KVM_STAT_VCPU },
	{ "tlbmiss_ld",	  VCPU_STAT(excep_exits[EXCCODE_TLBL]),	 KVM_STAT_VCPU },
	{ "tlbmiss_st",	  VCPU_STAT(excep_exits[EXCCODE_TLBS]),	 KVM_STAT_VCPU },
	{ "tlb_ifetch",	  VCPU_STAT(excep_exits[EXCCODE_TLBI]), KVM_STAT_VCPU },
	{ "tlbmod",	  VCPU_STAT(excep_exits[EXCCODE_TLBM]),	 KVM_STAT_VCPU },
	{ "tlbri",	  VCPU_STAT(excep_exits[EXCCODE_TLBRI]),	 KVM_STAT_VCPU },
	{ "tlbxi",	  VCPU_STAT(excep_exits[EXCCODE_TLBXI]),	 KVM_STAT_VCPU },
	{ "fp_disabled",  VCPU_STAT(excep_exits[EXCCODE_FPDIS]),  KVM_STAT_VCPU },
	{ "lsx_disabled", VCPU_STAT(excep_exits[EXCCODE_LSXDIS]), KVM_STAT_VCPU },
	{ "lasx_disabled", VCPU_STAT(excep_exits[EXCCODE_LASXDIS]), KVM_STAT_VCPU },
	{ "fpe",	  VCPU_STAT(excep_exits[EXCCODE_FPE]),		 KVM_STAT_VCPU },
	{ "watch",	  VCPU_STAT(excep_exits[EXCCODE_WATCH]),	 KVM_STAT_VCPU },
	{ "vz_gpsi",	  VCPU_STAT(excep_exits[EXCCODE_PSI]),	 KVM_STAT_VCPU },
	{ "vz_gsfc",	  VCPU_STAT(excep_exits[EXCCODE_GCM]),	 KVM_STAT_VCPU },
	{ "vz_hc",	  VCPU_STAT(excep_exits[EXCCODE_HYP]),	 KVM_STAT_VCPU },

	{ "lvz_rdcsr_cpu_feature",  VCPU_STAT(lvz_rdcsr_cpu_feature_exits),  KVM_STAT_VCPU },
	{ "lvz_rdcsr_misc_func",  VCPU_STAT(lvz_rdcsr_misc_func_exits),  KVM_STAT_VCPU },
	{ "lvz_rdcsr_ipi_access",  VCPU_STAT(lvz_rdcsr_ipi_access_exits),  KVM_STAT_VCPU },
	{ "lvz_cpucfg",  VCPU_STAT(lvz_cpucfg_exits),  KVM_STAT_VCPU },
	{ "lvz_huge_dec",  VCPU_STAT(lvz_huge_dec_exits),  KVM_STAT_VCPU },
	{ "lvz_huge_thp",  VCPU_STAT(lvz_huge_thp_exits),  KVM_STAT_VCPU },
	{ "lvz_huge_adj",  VCPU_STAT(lvz_huge_adjust_exits),  KVM_STAT_VCPU },
	{ "lvz_huge_set",  VCPU_STAT(lvz_huge_set_exits),  KVM_STAT_VCPU },
	{ "lvz_huge_merg",  VCPU_STAT(lvz_huge_merge_exits),  KVM_STAT_VCPU },

	{ "halt_successful_poll", VCPU_STAT(halt_successful_poll), KVM_STAT_VCPU },
	{ "halt_attempted_poll", VCPU_STAT(halt_attempted_poll), KVM_STAT_VCPU },
	{ "halt_poll_invalid", VCPU_STAT(halt_poll_invalid), KVM_STAT_VCPU },
	{ "halt_wakeup",  VCPU_STAT(halt_wakeup),	 KVM_STAT_VCPU },
	{NULL}
};

struct kvm_stats_debugfs_item debugfs_entries[] = {
	{ "remote_tlb_flush", VM_STAT(remote_tlb_flush), KVM_STAT_VM },
	{ "lvz_kvm_pip_read_exits", VM_STAT(lvz_kvm_pip_read_exits), KVM_STAT_VM },
	{ "lvz_kvm_pip_write_exits", VM_STAT(lvz_kvm_pip_write_exits), KVM_STAT_VM },
	{ "lvz_kvm_vm_ioctl_irq_line", VM_STAT(lvz_kvm_vm_ioctl_irq_line), KVM_STAT_VM },
	{ "lvz_kvm_ls7a_ioapic_update", VM_STAT(lvz_kvm_ls7a_ioapic_update), KVM_STAT_VM },
	{ "lvz_kvm_ls7a_ioapic_set_irq", VM_STAT(lvz_kvm_ls7a_ioapic_set_irq), KVM_STAT_VM },
	{ "lvz_kvm_ls7a_msi_irq", VM_STAT(lvz_kvm_ls7a_msi_irq), KVM_STAT_VM },
	{ "lvz_ls7a_ioapic_reg_write", VM_STAT(lvz_ls7a_ioapic_reg_write), KVM_STAT_VM },
	{ "lvz_ls7a_ioapic_reg_read", VM_STAT(lvz_ls7a_ioapic_reg_read), KVM_STAT_VM },
	{ "lvz_kvm_set_ls7a_ioapic", VM_STAT(lvz_kvm_set_ls7a_ioapic), KVM_STAT_VM },
	{ "lvz_kvm_get_ls7a_ioapic", VM_STAT(lvz_kvm_get_ls7a_ioapic), KVM_STAT_VM },
	{ "lvz_kvm_set_ls3a_ext_irq", VM_STAT(lvz_kvm_set_ls3a_ext_irq), KVM_STAT_VM },
	{ "lvz_kvm_get_ls3a_ext_irq", VM_STAT(lvz_kvm_get_ls3a_ext_irq), KVM_STAT_VM },
	{ "lvz_kvm_ls3a_ext_irq", VM_STAT(lvz_kvm_trigger_ls3a_ext_irq), KVM_STAT_VM },
	{NULL}
};

bool kvm_trace_guest_mode_change;

static unsigned int lvz_guest_mtlb_size;

int kvm_guest_mode_change_trace_reg(void)
{
	kvm_trace_guest_mode_change = 1;
	return 0;
}

void kvm_guest_mode_change_trace_unreg(void)
{
	kvm_trace_guest_mode_change = 0;
}

/*
 * XXXKYMA: We are simulatoring a processor that has the WII bit set in
 * Config7, so we are "runnable" if interrupts are pending
 */
int kvm_arch_vcpu_runnable(struct kvm_vcpu *vcpu)
{
	return !!(vcpu->arch.pending_exceptions);
}

bool kvm_arch_vcpu_in_kernel(struct kvm_vcpu *vcpu)
{
	return false;
}

int kvm_arch_vcpu_should_kick(struct kvm_vcpu *vcpu)
{
	return kvm_vcpu_exiting_guest_mode(vcpu) == IN_GUEST_MODE;
}
#ifdef CONFIG_PARAVIRT
void kvm_update_stolen_time(struct kvm_vcpu *vcpu)
{
	struct kvm_host_map map;
	struct kvm_steal_time *st;
	int ret = 0;

	if (vcpu->arch.st.guest_addr == 0)
		return;

	ret = kvm_map_gfn(vcpu, vcpu->arch.st.guest_addr >> PAGE_SHIFT,
				&map, &vcpu->arch.st.cache, false);
	if (ret) {
		kvm_info("%s ret:%d\n", __func__, ret);
		return;
	}
	st = map.hva + offset_in_page(vcpu->arch.st.guest_addr);
	if (st->version & 1)
		st->version += 1; /* first time write, random junk */
	st->version += 1;
	smp_wmb();
	st->steal += current->sched_info.run_delay -
		vcpu->arch.st.last_steal;
	vcpu->arch.st.last_steal = current->sched_info.run_delay;
	smp_wmb();
	st->version += 1;

	kvm_unmap_gfn(vcpu, &map, &vcpu->arch.st.cache, true, false);
}
#endif
/*
 * lvz_resize_guest_mtlb() - Attempt to resize guest MTLB.
 * @size:       Number of guest MTLB entries (0 < @size <= root MTLB entries).
 *
 * Attempt to resize the guest MTLB by writing guest Config registers. This is
 * necessary for cores with a shared root/guest TLB to avoid overlap with wired
 * entries in the root MTLB.
 */
static void lvz_resize_guest_mtlb(unsigned int size)
{
	unsigned long val = read_csr_gtlbc();
	val &= ~CSR_GTLBC_GMTLBSZ;
	val |= (size & CSR_GTLBC_GMTLBSZ);
	write_csr_gtlbc(val);
}

int kvm_arch_hardware_enable(void)
{
	unsigned int stlb_size, guest_mtlb_size;
	unsigned long gcfg = 0;

	/* First init gtlbc, gcfg, gstat, gintc. All guest use the same config */
	write_csr_gtlbc(0);
	write_csr_gcfg(0);
	write_csr_gstat(0);
	write_csr_gintc(0);
	/* Resize Guest MTLB size is half of root MTLB */
	stlb_size = current_cpu_data.tlbsize - current_cpu_data.tlbsizemtlb;
	guest_mtlb_size = (current_cpu_data.tlbsizemtlb >> 1) - 1;
	lvz_resize_guest_mtlb(guest_mtlb_size);
	current_cpu_data.guest.tlbsize = guest_mtlb_size + stlb_size;

	kvm_lvz_local_flush_guesttlb_all();

	/*
	 * Write the MTLB size, but if another CPU has already written,
	 * check it matches or we won't provide a consistent view to the
	 * guest. If this ever happens it suggests an asymmetric number
	 * of wired entries.
	 */
	if (cmpxchg(&lvz_guest_mtlb_size, 0, guest_mtlb_size) &&
			WARN(guest_mtlb_size != lvz_guest_mtlb_size,
				"Available guest MTLB size mismatch"))
		return -EINVAL;

	/*
	 * Enable virtualization features granting guest direct control of
	 * certain features:
	 * GCI=2:       Trap on init or unimplement cache instruction.
	 * TORU=0:      Trap on Root Unimplement.
	 * CACTRL=1:    Root control cache.
	 * TOP=0:       Trap on Previlege.
	 * TOE=0:       Trap on Exception.
	 * TIT=0:       Trap on Timer.
	 */
	if (cpu_has_gcip_all)
		gcfg |= CSR_GCFG_GCI_SECURE;
	if (cpu_has_matc_root)
		gcfg |= CSR_GCFG_MATC_ROOT;

	gcfg |= CSR_GCFG_TIT;
	write_csr_gcfg(gcfg);

	kvm_lvz_local_flush_roottlb_all_guests();

	GUESTID_MASK = current_cpu_data.guestid_mask;
	GUESTID_FIRST_VERSION = (unsigned long)(GUESTID_MASK + 1);
	GUESTID_VERSION_MASK = (unsigned long)~GUESTID_MASK;
	current_cpu_data.guestid_cache = GUESTID_FIRST_VERSION;

	/* Set gtlbc.use_rid for enable RID */
	set_csr_gtlbc(CSR_GTLBC_USERID);
	kvm_debug("gtlbc:%llx gintc:%llx gstat:%llx gcfg:%llx",
			read_csr_gtlbc(), read_csr_gintc(),
			read_csr_gstat(), read_csr_gcfg());
	return 0;
}

void kvm_arch_hardware_disable(void)
{
	write_csr_gcfg(0);
	write_csr_gtlbc(0);
	write_csr_gstat(0);
	write_csr_gintc(0);

	/* Flush any remaining guest TLB entries */
	kvm_lvz_local_flush_guesttlb_all();
	kvm_lvz_local_flush_roottlb_all_guests();
}

int kvm_arch_hardware_setup(void)
{
	return 0;
}

void kvm_arch_check_processor_compat(void *rtn)
{
	*(int *)rtn = 0;
}

int kvm_arch_init_vm(struct kvm *kvm, unsigned long type)
{
	if (type == KVM_VM_LOONGARCH_AUTO)
		type = KVM_VM_LOONGARCH_VZ;

	/* only loongarch vz is supported for the present */
	if (type != KVM_VM_LOONGARCH_VZ)
		return -EINVAL;
	kvm_lvz_ops_init(kvm);

	/* Allocate page table to map GPA -> RPA */
	kvm->arch.gpa_mm.pgd = kvm_pgd_alloc();
	if (!kvm->arch.gpa_mm.pgd)
		return -ENOMEM;

	kvm->arch.cpucfg_lasx = (read_cpucfg(LOONGARCH_CPUCFG2) &
					  CPUCFG2_LASX);
	/* Initialize to 1 for check only once */
	kvm->arch.hypcall_check = 1;

	lvz_iocsr_init(kvm);

	return 0;
}

static int lvcpu_stat_get(void *address, u64 *val)
{
	*val = *(u64 *)address;
	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(lvcpu_stat_fops, lvcpu_stat_get, NULL, "%llu\n");

static int vcpu_pid_get(void *arg, u64 *val)
{
	struct kvm_vcpu *vcpu = (struct kvm_vcpu *)arg;
	if (vcpu)
		*val = pid_vnr(vcpu->pid);
	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(vcpu_pid_fops, vcpu_pid_get, NULL, "%llu\n");

bool kvm_arch_has_vcpu_debugfs(void)
{
	return true;
}

int kvm_arch_create_vcpu_debugfs(struct kvm_vcpu *vcpu)
{
	struct kvm_stats_debugfs_item *p;
	debugfs_create_file("pid", 0444, vcpu->debugfs_dentry, vcpu, &vcpu_pid_fops);
	for (p = vcpu_debugfs_entries; p->name && p->kind == KVM_STAT_VCPU; ++p) {
		debugfs_create_file(p->name, 0444, vcpu->debugfs_dentry,
				(void *)vcpu + p->offset, &lvcpu_stat_fops);
	}

	return 0;
}

static void kvm_free_vcpus(struct kvm *kvm)
{
	unsigned int i;
	struct kvm_vcpu *vcpu;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		kvm_arch_vcpu_free(vcpu);
	}

	mutex_lock(&kvm->lock);

	for (i = 0; i < atomic_read(&kvm->online_vcpus); i++)
		kvm->vcpus[i] = NULL;

	atomic_set(&kvm->online_vcpus, 0);

	mutex_unlock(&kvm->lock);
}

void kvm_arch_destroy_vm(struct kvm *kvm)
{
	kvm_destroy_ls3a_ipi(kvm);
	kvm_destroy_ls7a_ioapic(kvm);
	kvm_destroy_ls3a_ext_irq(kvm);
	kvm_free_vcpus(kvm);
	kvm_loongarch_destroy_mm(kvm);
}

long kvm_arch_dev_ioctl(struct file *filp, unsigned int ioctl,
			unsigned long arg)
{
	return -ENOIOCTLCMD;
}

int kvm_arch_create_memslot(struct kvm *kvm, struct kvm_memory_slot *slot,
			    unsigned long npages)
{
	return 0;
}

int kvm_arch_prepare_memory_region(struct kvm *kvm,
				   struct kvm_memory_slot *memslot,
				   const struct kvm_userspace_memory_region *mem,
				   enum kvm_mr_change change)
{
	return 0;
}

struct kvm_vcpu *kvm_arch_vcpu_create(struct kvm *kvm, unsigned int id)
{
	int err;
	struct kvm_vcpu *vcpu = kzalloc(sizeof(struct kvm_vcpu), GFP_KERNEL);

	if (!vcpu) {
		err = -ENOMEM;
		goto out;
	}

	err = kvm_vcpu_init(vcpu, kvm, id);

	if (err)
		goto out_free_cpu;

	kvm->arch.online_vcpus = id + 1;

	vcpu->arch.host_eentry = eentry;
	vcpu->arch.guest_eentry = (unsigned long)kvm_exception_entry;
	vcpu->arch.vcpu_run = kvm_enter_guest;
	vcpu->arch.handle_exit = kvm_loongarch_handle_exit;
	vcpu->arch.csr = kzalloc(sizeof(struct loongarch_csrs), GFP_KERNEL);
	/*
	 * kvm all exceptions share one exception entry, and host <-> guest switch
	 * also switch excfg.VS field, keep host excfg.VS info here
	 */
	vcpu->arch.host_ecfg = (read_csr_ecfg() & CSR_ECFG_VS);

	if (!vcpu->arch.csr) {
		err = -ENOMEM;
		goto out_uninit_cpu;
	}

	/* Init */
	vcpu->arch.last_sched_cpu = -1;
	vcpu->arch.last_exec_cpu = -1;

	return vcpu;

out_uninit_cpu:
	kvm_vcpu_uninit(vcpu);

out_free_cpu:
	kfree(vcpu);

out:
	return ERR_PTR(err);
}

void kvm_arch_vcpu_free(struct kvm_vcpu *vcpu)
{
	struct gfn_to_pfn_cache *cache = &vcpu->arch.st.cache;

	hrtimer_cancel(&vcpu->arch.swtimer);

	kvm_vcpu_uninit(vcpu);
	kvm_mmu_free_memory_caches(vcpu);
	kvm_release_pfn(cache->pfn, cache->dirty, cache);
	kfree(vcpu->arch.csr);
	kfree(vcpu);
}

void kvm_arch_vcpu_destroy(struct kvm_vcpu *vcpu)
{
	kvm_arch_vcpu_free(vcpu);
}
#define KVM_GUESTDBG_VALID_MASK (KVM_GUESTDBG_ENABLE | \
		KVM_GUESTDBG_USE_SW_BP |\
		KVM_GUESTDBG_SINGLESTEP | KVM_GUESTDBG_USE_HW_BP)
int kvm_arch_vcpu_ioctl_set_guest_debug(struct kvm_vcpu *vcpu,
					struct kvm_guest_debug *dbg)
{
	int ret = 0;

	if (dbg->control & ~KVM_GUESTDBG_VALID_MASK) {
		ret = -EINVAL;
		goto out;
	}
	if (dbg->control & KVM_GUESTDBG_ENABLE) {
		vcpu->guest_debug = dbg->control;
		/* Hardware breakpoint */
		if (vcpu->guest_debug & KVM_GUESTDBG_USE_HW_BP) {
			/* If hw breakpoint used in guest now, return false */
			if (vcpu->arch.aux_inuse & KVM_LARCH_HWBP) {
				vcpu->guest_debug &= ~KVM_GUESTDBG_USE_HW_BP;
				ret = -EINVAL;
				goto out;
			} else {
				vcpu->arch.guest_debug = dbg->arch;
			}
		}
	} else {
		vcpu->guest_debug = 0;
	}
out:
	return ret;
}

int kvm_arch_vcpu_ioctl_run(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	int r = -EINTR;
	struct kvm_ops *kvm_ops;

	vcpu_load(vcpu);

	kvm_sigset_activate(vcpu);

	if (vcpu->mmio_needed) {
		if (!vcpu->mmio_is_write)
			kvm_larch_complete_ld(vcpu, run);
		vcpu->mmio_needed = 0;
	} else if (vcpu->arch.is_hypcall) {
		/* set return value for hypercall v0 register */
		vcpu->arch.gprs[REG_V0] = run->hypercall.ret;
		vcpu->arch.is_hypcall = 0;
	}

	if (run->immediate_exit)
		goto out;

	lose_fpu(1);

#ifdef CONFIG_PARAVIRT
	if (kvm_check_request(KVM_REQ_RECORD_STEAL, vcpu))
		kvm_update_stolen_time(vcpu);
#endif
	local_irq_disable();
	guest_enter_irqoff();
	trace_kvm_enter(vcpu);

	/*
	 * Make sure the read of VCPU requests in vcpu_run() callback is not
	 * reordered ahead of the write to vcpu->mode, or we could miss a TLB
	 * flush request while the requester sees the VCPU as outside of guest
	 * mode and not needing an IPI.
	 */
	smp_store_mb(vcpu->mode, IN_GUEST_MODE);

	kvm_ops = vcpu->kvm->arch.kvm_ops;
	r = kvm_ops->vcpu_run(run, vcpu);

	trace_kvm_out(vcpu);
	guest_exit_irqoff();
	local_irq_enable();

out:
	kvm_sigset_deactivate(vcpu);

	vcpu_put(vcpu);
	return r;
}

int kvm_vcpu_ioctl_interrupt(struct kvm_vcpu *vcpu,
			     struct kvm_loongarch_interrupt *irq)
{
	int intr = (int)irq->irq;
	struct kvm_vcpu *dvcpu = NULL;
	struct kvm_ops *kvm_ops = vcpu->kvm->arch.kvm_ops;

	if (irq->cpu == -1)
		dvcpu = vcpu;
	else
		dvcpu = vcpu->kvm->vcpus[irq->cpu];

	if (intr > 0) {
		kvm_ops->queue_io_int(dvcpu, intr);

	} else if (intr < 0) {
		kvm_ops->dequeue_io_int(dvcpu, -intr);
	} else {
		kvm_err("%s: invalid interrupt ioctl (%d:%d)\n", __func__,
			irq->cpu, irq->irq);
		return -EINVAL;
	}

	dvcpu->arch.wait = 0;
	kvm_vcpu_kick(dvcpu);

	return 0;
}

int kvm_arch_vcpu_ioctl_get_mpstate(struct kvm_vcpu *vcpu,
				    struct kvm_mp_state *mp_state)
{
	return -ENOIOCTLCMD;
}

int kvm_arch_vcpu_ioctl_set_mpstate(struct kvm_vcpu *vcpu,
				    struct kvm_mp_state *mp_state)
{
	return -ENOIOCTLCMD;
}

static int kvm_loongarch_get_reg(struct kvm_vcpu *vcpu,
			    const struct kvm_one_reg *reg)
{
	int ret;
	s64 v;
	struct kvm_ops *kvm_ops;

	kvm_ops = vcpu->kvm->arch.kvm_ops;
	ret = kvm_ops->get_one_reg(vcpu, reg, &v);
	if (ret)
		return ret;

	ret = -EINVAL;
	if ((reg->id & KVM_REG_SIZE_MASK) == KVM_REG_SIZE_U64) {
		u64 __user *uaddr64 = (u64 __user *)(long)reg->addr;

		ret = put_user(v, uaddr64);
	} else if ((reg->id & KVM_REG_SIZE_MASK) == KVM_REG_SIZE_U32) {
		u32 __user *uaddr32 = (u32 __user *)(long)reg->addr;
		u32 v32 = (u32)v;

		ret = put_user(v32, uaddr32);
	}

	return ret;
}

static int kvm_loongarch_set_reg(struct kvm_vcpu *vcpu,
			    const struct kvm_one_reg *reg)
{
	s64 v;
	int ret;
	struct kvm_ops *kvm_ops;

	ret = -EINVAL;
	if ((reg->id & KVM_REG_SIZE_MASK) == KVM_REG_SIZE_U64) {
		u64 __user *uaddr64 = (u64 __user *)(long)reg->addr;
		ret = get_user(v, uaddr64);
	} else if ((reg->id & KVM_REG_SIZE_MASK) == KVM_REG_SIZE_U32) {
		u32 __user *uaddr32 = (u32 __user *)(long)reg->addr;
		s32 v32;

		ret = get_user(v32, uaddr32);
		v = (s64)v32;
	}

	if (ret)
		return -EFAULT;

	kvm_ops = vcpu->kvm->arch.kvm_ops;
	return kvm_ops->set_one_reg(vcpu, reg, v);
}

static int kvm_vcpu_ioctl_enable_cap(struct kvm_vcpu *vcpu,
				     struct kvm_enable_cap *cap)
{
	int r = 0;

	if (!kvm_vm_ioctl_check_extension(vcpu->kvm, cap->cap))
		return -EINVAL;
	if (cap->flags)
		return -EINVAL;
	if (cap->args[0])
		return -EINVAL;

	switch (cap->cap) {
	case KVM_CAP_LOONGARCH_FPU:
		vcpu->arch.fpu_enabled = true;
		break;
	case KVM_CAP_LOONGARCH_LSX:
		vcpu->arch.lsx_enabled = true;
		break;
	default:
		r = -EINVAL;
		break;
	}

	return r;
}

long kvm_arch_vcpu_async_ioctl(struct file *filp, unsigned int ioctl,
			       unsigned long arg)
{
	struct kvm_vcpu *vcpu = filp->private_data;
	void __user *argp = (void __user *)arg;

	if (ioctl == KVM_INTERRUPT) {
		struct kvm_loongarch_interrupt irq;

		if (copy_from_user(&irq, argp, sizeof(irq)))
			return -EFAULT;
		kvm_debug("[%d] %s: irq: %d\n", vcpu->vcpu_id, __func__,
			  irq.irq);

		return kvm_vcpu_ioctl_interrupt(vcpu, &irq);
	}

	return -ENOIOCTLCMD;
}

int kvm_vm_ioctl_irq_line(struct kvm *kvm, struct kvm_irq_level *irq_level,
			  bool line_status)
{
	u32 irq = irq_level->irq;
	unsigned int irq_type, vcpu_idx, irq_num, ret;
	int nrcpus = atomic_read(&kvm->online_vcpus);
	bool level = irq_level->level;
	unsigned long flags;

	irq_type = (irq >> KVM_LOONGSON_IRQ_TYPE_SHIFT) & KVM_LOONGSON_IRQ_TYPE_MASK;
	vcpu_idx = (irq >> KVM_LOONGSON_IRQ_VCPU_SHIFT) & KVM_LOONGSON_IRQ_VCPU_MASK;
	irq_num = (irq >> KVM_LOONGSON_IRQ_NUM_SHIFT) & KVM_LOONGSON_IRQ_NUM_MASK;

	switch (irq_type) {
	case KVM_LOONGSON_IRQ_TYPE_IOAPIC:
		if (!ls7a_ioapic_in_kernel(kvm))
			return -ENXIO;

		if (vcpu_idx >= nrcpus)
			return -EINVAL;

		ls7a_ioapic_lock(ls7a_ioapic_irqchip(kvm), &flags);
		ret = kvm_ls7a_ioapic_set_irq(kvm, irq_num, level);
		ls7a_ioapic_unlock(ls7a_ioapic_irqchip(kvm), &flags);
		return ret;
	}
	kvm->stat.lvz_kvm_vm_ioctl_irq_line++;

	return -EINVAL;
}

static int kvm_vm_ioctl_get_irqchip(struct kvm *kvm, struct loongarch_kvm_irqchip *chip)
{
	int r, dlen;

	r = 0;
	dlen = chip->len - sizeof(struct loongarch_kvm_irqchip);
	switch (chip->chip_id) {
	case KVM_IRQCHIP_LS7A_IOAPIC:
		if (dlen != sizeof(struct kvm_ls7a_ioapic_state)) {
			kvm_err("get ls7a state err dlen:%d\n", dlen);
			goto dlen_err;
		}
		r = kvm_get_ls7a_ioapic(kvm, (void *)chip->data);
		break;
	case KVM_IRQCHIP_LS3A_GIPI:
		if (dlen != sizeof(gipiState)) {
			kvm_err("get gipi state err dlen:%d\n", dlen);
			goto dlen_err;
		}
		r = kvm_get_ls3a_ipi(kvm, (void *)chip->data);
		break;
	case KVM_IRQCHIP_LS3A_HT_IRQ:
	case KVM_IRQCHIP_LS3A_ROUTE:
		break;
	case KVM_IRQCHIP_LS3A_EXTIRQ:
		if (dlen != sizeof(struct kvm_loongarch_ls3a_extirq_state)) {
			kvm_err("get extioi state err dlen:%d\n", dlen);
			goto dlen_err;
		}
		r = kvm_get_ls3a_extirq(kvm, (void *)chip->data);
		break;
	case KVM_IRQCHIP_LS3A_IPMASK:
		break;
	default:
		r = -EINVAL;
		break;
	}
	return r;
dlen_err:
	r = -EINVAL;
	return r;
}

static int kvm_vm_ioctl_set_irqchip(struct kvm *kvm, struct loongarch_kvm_irqchip *chip)
{
	int r, dlen;

	r = 0;
	dlen = chip->len - sizeof(struct loongarch_kvm_irqchip);
	switch (chip->chip_id) {
	case KVM_IRQCHIP_LS7A_IOAPIC:
		if (dlen != sizeof(struct kvm_ls7a_ioapic_state)) {
			kvm_err("set ls7a state err dlen:%d\n", dlen);
			goto dlen_err;
		}
		r = kvm_set_ls7a_ioapic(kvm, (void *)chip->data);
		break;
	case KVM_IRQCHIP_LS3A_GIPI:
		if (dlen != sizeof(gipiState)) {
			kvm_err("set gipi state err dlen:%d\n", dlen);
			goto dlen_err;
		}
		r = kvm_set_ls3a_ipi(kvm, (void *)chip->data);
		break;
	case KVM_IRQCHIP_LS3A_HT_IRQ:
	case KVM_IRQCHIP_LS3A_ROUTE:
		break;
	case KVM_IRQCHIP_LS3A_EXTIRQ:
		if (dlen != sizeof(struct kvm_loongarch_ls3a_extirq_state)) {
			kvm_err("set extioi state err dlen:%d\n", dlen);
			goto dlen_err;
		}
		r = kvm_set_ls3a_extirq(kvm, (void *)chip->data);
		break;
	case KVM_IRQCHIP_LS3A_IPMASK:
		break;
	default:
		r = -EINVAL;
		break;
	}
	return r;
dlen_err:
	r = -EINVAL;
	return r;
}

/*
 * Read or write a bunch of msrs. All parameters are kernel addresses.
 *
 * @return number of msrs set successfully.
 */
static int __msr_io(struct kvm_vcpu *vcpu, struct kvm_msrs *msrs,
		struct kvm_csr_entry *entries,
		int (*do_msr)(struct kvm_vcpu *vcpu,
			unsigned index, u64 *data, int force))
{
	int i;

	for (i = 0; i < msrs->ncsrs; ++i)
		if (do_msr(vcpu, entries[i].index, &entries[i].data, 1))
			break;

	return i;
}

static int msr_io(struct kvm_vcpu *vcpu, struct kvm_msrs __user *user_msrs,
		int (*do_msr)(struct kvm_vcpu *vcpu,
			unsigned index, u64 *data, int force))
{
	struct kvm_msrs msrs;
	struct kvm_csr_entry *entries;
	int r, n;
	unsigned size;

	r = -EFAULT;
	if (copy_from_user(&msrs, user_msrs, sizeof msrs))
		goto out;

	r = -E2BIG;
	if (msrs.ncsrs >= CSR_ALL_SIZE)
		goto out;

	size = sizeof(struct kvm_csr_entry) * msrs.ncsrs;
	entries = memdup_user(user_msrs->entries, size);
	if (IS_ERR(entries)) {
		r = PTR_ERR(entries);
		goto out;
	}

	r = n = __msr_io(vcpu, &msrs, entries, do_msr);
	if (r < 0)
		goto out_free;

	r = -EFAULT;
	if (copy_to_user(user_msrs->entries, entries, size))
		goto out_free;

	r = n;

out_free:
	kfree(entries);
out:
	return r;
}

long kvm_arch_vcpu_ioctl(struct file *filp, unsigned int ioctl,
			 unsigned long arg)
{
	struct kvm_vcpu *vcpu = filp->private_data;
	void __user *argp = (void __user *)arg;
	long r;

	vcpu_load(vcpu);

	switch (ioctl) {
	case KVM_SET_ONE_REG:
	case KVM_GET_ONE_REG: {
		struct kvm_one_reg reg;

		r = -EFAULT;
		if (copy_from_user(&reg, argp, sizeof(reg)))
			break;
		if (ioctl == KVM_SET_ONE_REG)
			r = kvm_loongarch_set_reg(vcpu, &reg);
		else
			r = kvm_loongarch_get_reg(vcpu, &reg);
		break;
	}
	case KVM_ENABLE_CAP: {
		struct kvm_enable_cap cap;

		r = -EFAULT;
		if (copy_from_user(&cap, argp, sizeof(cap)))
			break;
		r = kvm_vcpu_ioctl_enable_cap(vcpu, &cap);
		break;
	}
	case KVM_CHECK_EXTENSION: {
		unsigned int ext;
		if (copy_from_user(&ext, argp, sizeof(ext)))
			return -EFAULT;
		switch (ext) {
		case KVM_CAP_LOONGARCH_FPU:
			r = !!cpu_has_fpu;
			break;
		case KVM_CAP_LOONGARCH_LSX:
			r = !!cpu_has_lsx;
			break;
		default:
			break;
		}
	}

	case KVM_LOONGARCH_GET_VCPU_STATE:
	{
		int i;
		struct  kvm_loongarch_vcpu_state vcpu_state;
		r = -EFAULT;

		vcpu_state.online_vcpus = vcpu->kvm->arch.online_vcpus;
		vcpu_state.is_migrate = 1;
		for (i = 0; i < 4; i++)
			vcpu_state.core_ext_ioisr[i] = vcpu->arch.core_ext_ioisr[i];

		vcpu_state.pending_exceptions =  vcpu->arch.pending_exceptions;
		vcpu_state.pending_exceptions_clr =  vcpu->arch.pending_exceptions_clr;

		if (copy_to_user(argp, &vcpu_state, sizeof(struct kvm_loongarch_vcpu_state)))
			break;
		r = 0;
		break;
	}

	case KVM_LOONGARCH_SET_VCPU_STATE:
	{
		int i;
		struct  kvm_loongarch_vcpu_state vcpu_state;
		r = -EFAULT;

		if (copy_from_user(&vcpu_state, argp, sizeof(struct kvm_loongarch_vcpu_state)))
			return -EFAULT;

		vcpu->kvm->arch.online_vcpus = vcpu_state.online_vcpus;
		vcpu->kvm->arch.is_migrate = vcpu_state.is_migrate;
		for (i = 0; i < 4; i++)
			 vcpu->arch.core_ext_ioisr[i] = vcpu_state.core_ext_ioisr[i];

		vcpu->arch.pending_exceptions = vcpu_state.pending_exceptions;
		vcpu->arch.pending_exceptions_clr = vcpu_state.pending_exceptions_clr;
		r = 0;
		break;
	}
	case KVM_GET_MSRS: {
		r = msr_io(vcpu, argp, lvz_getcsr);
		break;
	}
	case KVM_SET_MSRS: {
		r = msr_io(vcpu, argp, lvz_setcsr);
		break;
	}
	default:
		r = -ENOIOCTLCMD;
	}

	vcpu_put(vcpu);
	return r;
}

/**
 * kvm_vm_ioctl_get_dirty_log - get and clear the log of dirty pages in a slot
 * @kvm: kvm instance
 * @log: slot id and address to which we copy the log
 *
 * Steps 1-4 below provide general overview of dirty page logging. See
 * kvm_get_dirty_log_protect() function description for additional details.
 *
 * We call kvm_get_dirty_log_protect() to handle steps 1-3, upon return we
 * always flush the TLB (step 4) even if previous step failed  and the dirty
 * bitmap may be corrupt. Regardless of previous outcome the KVM logging API
 * does not preclude user space subsequent dirty log read. Flushing TLB ensures
 * writes will be marked dirty for next log read.
 *
 *   1. Take a snapshot of the bit and clear it if needed.
 *   2. Write protect the corresponding page.
 *   3. Copy the snapshot to the userspace.
 *   4. Flush TLB's if needed.
 */
int kvm_vm_ioctl_get_dirty_log(struct kvm *kvm, struct kvm_dirty_log *log)
{
	struct kvm_memslots *slots;
	struct kvm_memory_slot *memslot;
	bool is_dirty = false;
	int r;

	mutex_lock(&kvm->slots_lock);

	r = kvm_get_dirty_log_protect(kvm, log, &is_dirty);

	if (is_dirty) {
		slots = kvm_memslots(kvm);
		memslot = id_to_memslot(slots, log->slot);

		/* Let implementation handle TLB/GVA invalidation */
		kvm->arch.kvm_ops->flush_shadow_memslot(kvm, memslot);
	}

	mutex_unlock(&kvm->slots_lock);
	return r;
}

long kvm_arch_vm_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg)
{
	struct kvm *kvm = filp->private_data;
	void __user *argp = (void __user *)arg;
	long r;

	switch (ioctl) {
	case KVM_CREATE_IRQCHIP:
	{
		mutex_lock(&kvm->lock);
		r = -EEXIST;
		if (kvm->arch.v_ioapic)
			goto create_irqchip_unlock;

		r = kvm_create_ls7a_ioapic(kvm);
		if (r < 0)
			goto create_irqchip_unlock;
		r = kvm_create_ls3a_ipi(kvm);
		if (r < 0) {
			mutex_lock(&kvm->slots_lock);
			kvm_destroy_ls7a_ioapic(kvm);
			mutex_unlock(&kvm->slots_lock);
			goto create_irqchip_unlock;
		}
		r = kvm_create_ls3a_ext_irq(kvm);
		if (r < 0) {
			mutex_lock(&kvm->slots_lock);
			kvm_destroy_ls3a_ipi(kvm);
			kvm_destroy_ls7a_ioapic(kvm);
			mutex_unlock(&kvm->slots_lock);
		}
		irqchip_debug_init(kvm);
		/* Write kvm->irq_routing before kvm->arch.vpic.  */
		smp_wmb();
create_irqchip_unlock:
		mutex_unlock(&kvm->lock);
		break;
	}
	case KVM_GET_IRQCHIP: {
		struct loongarch_kvm_irqchip *kchip;
		struct loongarch_kvm_irqchip uchip;
		if (copy_from_user(&uchip, argp, sizeof(struct loongarch_kvm_irqchip)))
			goto out;
		kchip = memdup_user(argp, uchip.len);
		if (IS_ERR(kchip)) {
			r = PTR_ERR(kchip);
			goto out;
		}

		r = -ENXIO;
		if (!ls7a_ioapic_in_kernel(kvm))
			goto get_irqchip_out;
		r = kvm_vm_ioctl_get_irqchip(kvm, kchip);
		if (r)
			goto get_irqchip_out;
		if (copy_to_user(argp, kchip, kchip->len))
			goto get_irqchip_out;
		r = 0;
get_irqchip_out:
		kfree(kchip);
		break;
	}
	case KVM_SET_IRQCHIP: {
		struct loongarch_kvm_irqchip *kchip;
		struct loongarch_kvm_irqchip uchip;
		if (copy_from_user(&uchip, argp, sizeof(struct loongarch_kvm_irqchip)))
			goto out;

		kchip = memdup_user(argp, uchip.len);
		if (IS_ERR(kchip)) {
			r = PTR_ERR(kchip);
			goto out;
		}

		r = -ENXIO;
		if (!ls7a_ioapic_in_kernel(kvm))
			goto set_irqchip_out;
		r = kvm_vm_ioctl_set_irqchip(kvm, kchip);
		if (r)
			goto set_irqchip_out;
		r = 0;
set_irqchip_out:
		kfree(kchip);
		break;
	}
	case KVM_LOONGARCH_GET_IOCSR:
	{
		r = lvz_iocsr_get(kvm, argp);
		break;
	}
	case KVM_LOONGARCH_SET_IOCSR:
	{
		r = lvz_iocsr_set(kvm, argp);
		break;
	}
	case KVM_LOONGARCH_SET_CPUCFG:
	{
		r = 0;
		if (copy_from_user(&kvm->arch.cpucfgs, argp, sizeof(struct kvm_cpucfg)))
			r = -EFAULT;
		break;
	}
	case KVM_LOONGARCH_GET_CPUCFG:
	{
		r = 0;
		if (copy_to_user(argp, &kvm->arch.cpucfgs, sizeof(struct kvm_cpucfg)))
		   r = -EFAULT;
		break;
	}
	default:
		r = -ENOIOCTLCMD;
	}
out:

	return r;
}

int kvm_arch_init(void *opaque)
{
	return 0;
}

void kvm_arch_exit(void)
{
}

int kvm_arch_vcpu_ioctl_get_sregs(struct kvm_vcpu *vcpu,
				  struct kvm_sregs *sregs)
{
	return -ENOIOCTLCMD;
}

int kvm_arch_vcpu_ioctl_set_sregs(struct kvm_vcpu *vcpu,
				  struct kvm_sregs *sregs)
{
	return -ENOIOCTLCMD;
}

void kvm_arch_vcpu_postcreate(struct kvm_vcpu *vcpu)
{
}

int kvm_arch_vcpu_ioctl_get_fpu(struct kvm_vcpu *vcpu, struct kvm_fpu *fpu)
{
	int i = 0;

	/* no need vcpu_load and vcpu_put */
	fpu->fcsr = vcpu->arch.fpu.fcsr;
	fpu->vcsr = vcpu->arch.fpu.vcsr;
	fpu->fcc = vcpu->arch.fpu.fcc;
	for (i = 0; i < NUM_FPU_REGS; i++)
		memcpy(&fpu->fpr[i], &vcpu->arch.fpu.fpr[i], FPU_REG_WIDTH / 64);

	return 0;
}

int kvm_arch_vcpu_ioctl_set_fpu(struct kvm_vcpu *vcpu, struct kvm_fpu *fpu)
{
	int i = 0;

	/* no need vcpu_load and vcpu_put */
	vcpu->arch.fpu.fcsr = fpu->fcsr;
	vcpu->arch.fpu.vcsr = fpu->vcsr;
	vcpu->arch.fpu.fcc = fpu->fcc;
	for (i = 0; i < NUM_FPU_REGS; i++)
		memcpy(&vcpu->arch.fpu.fpr[i], &fpu->fpr[i], FPU_REG_WIDTH / 64);

	return 0;
}

vm_fault_t kvm_arch_vcpu_fault(struct kvm_vcpu *vcpu, struct vm_fault *vmf)
{
	return VM_FAULT_SIGBUS;
}

int kvm_vm_ioctl_check_extension(struct kvm *kvm, long ext)
{
	int r;

	switch (ext) {
	case KVM_CAP_ONE_REG:
	case KVM_CAP_ENABLE_CAP:
	case KVM_CAP_READONLY_MEM:
	case KVM_CAP_SYNC_MMU:
#ifdef CONFIG_HAVE_LS_KVM_MSI
	case KVM_CAP_SIGNAL_MSI:
#endif
	case KVM_CAP_IMMEDIATE_EXIT:
		r = 1;
		break;
	case KVM_CAP_NR_VCPUS:
		r = num_online_cpus();
		break;
	case KVM_CAP_MAX_VCPUS:
		r = KVM_MAX_VCPUS;
		break;
	case KVM_CAP_MAX_VCPU_ID:
		r = KVM_MAX_VCPU_ID;
		break;
	case KVM_CAP_NR_MEMSLOTS:
		r = KVM_USER_MEM_SLOTS;
		break;
	case KVM_CAP_LOONGARCH_FPU:
		/* We don't handle systems with inconsistent cpu_has_fpu */
		r = !!cpu_has_fpu;
		break;
	case KVM_CAP_LOONGARCH_LSX:
		/*
		 * We don't support LSX vector partitioning yet:
		 * 1) It would require explicit support which can't be tested
		 *    yet due to lack of support in current hardware.
		 * 2) It extends the state that would need to be saved/restored
		 *    by e.g. QEMU for migration.
		 *
		 * When vector partitioning hardware becomes available, support
		 * could be added by requiring a flag when enabling
		 * KVM_CAP_LOONGARCH_LSX capability to indicate that userland knows
		 * to save/restore the appropriate extra state.
		 */
		r = cpu_has_lsx;
		break;
	case KVM_CAP_IRQCHIP:
	case KVM_CAP_IOEVENTFD:
		/* we wouldn't be here unless cpu_has_lvz */
		r = 1;
		break;
	case KVM_CAP_LOONGARCH_VZ:
		/* get user defined kvm version */
		r = KVM_LOONGARCH_VERSION;
		break;
	default:
		r = 0;
		break;
	}
	return r;
}

int kvm_cpu_has_pending_timer(struct kvm_vcpu *vcpu)
{
	return kvm_loongarch_pending_timer(vcpu) ||
		kvm_read_hw_gcsr(LOONGARCH_CSR_ESTAT) &
			(1 << (EXCCODE_TIMER - EXCCODE_INT_START));
}

int kvm_arch_vcpu_dump_regs(struct kvm_vcpu *vcpu)
{
	int i;
	struct loongarch_csrs *csr;

	if (!vcpu)
		return -1;

	kvm_debug("VCPU Register Dump:\n");
	kvm_debug("\tpc = 0x%08lx\n", vcpu->arch.pc);
	kvm_debug("\texceptions: %08lx\n", vcpu->arch.pending_exceptions);

	for (i = 0; i < 32; i += 4) {
		kvm_debug("\tgpr%02d: %08lx %08lx %08lx %08lx\n", i,
		       vcpu->arch.gprs[i],
		       vcpu->arch.gprs[i + 1],
		       vcpu->arch.gprs[i + 2], vcpu->arch.gprs[i + 3]);
	}

	csr = vcpu->arch.csr;
	kvm_debug("\tCRMOD: 0x%08llx, exst: 0x%08llx\n",
		  kvm_read_hw_gcsr(LOONGARCH_CSR_CRMD),
		  kvm_read_hw_gcsr(LOONGARCH_CSR_ESTAT));

	kvm_debug("\tERA: 0x%08llx\n", kvm_read_hw_gcsr(LOONGARCH_CSR_ERA));

	return 0;
}

int kvm_arch_vcpu_ioctl_set_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
{
	int i;

	vcpu_load(vcpu);

	for (i = 1; i < ARRAY_SIZE(vcpu->arch.gprs); i++)
		vcpu->arch.gprs[i] = regs->gpr[i];
	vcpu->arch.gprs[0] = 0; /* zero is special, and cannot be set. */
	vcpu->arch.pc = regs->pc;

	vcpu_put(vcpu);
	return 0;
}

int kvm_arch_vcpu_ioctl_get_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
{
	int i;

	vcpu_load(vcpu);

	for (i = 0; i < ARRAY_SIZE(vcpu->arch.gprs); i++)
		regs->gpr[i] = vcpu->arch.gprs[i];

	regs->pc = vcpu->arch.pc;

	vcpu_put(vcpu);
	return 0;
}

static void kvm_swtimer_func(unsigned long data)
{
	struct kvm_vcpu *vcpu = (struct kvm_vcpu *)data;
	struct kvm_ops *kvm_ops = vcpu->kvm->arch.kvm_ops;

	kvm_ops->queue_timer_int(vcpu);

	vcpu->arch.wait = 0;
	if (swq_has_sleeper(&vcpu->wq))
		swake_up_one(&vcpu->wq);
}

/* low level hrtimer wake routine */
static enum hrtimer_restart kvm_swtimer_wakeup(struct hrtimer *timer)
{
	struct kvm_vcpu *vcpu;

	vcpu = container_of(timer, struct kvm_vcpu, arch.swtimer);
	kvm_swtimer_func((unsigned long) vcpu);
	return kvm_count_timeout(vcpu);
}

int kvm_arch_vcpu_init(struct kvm_vcpu *vcpu)
{
	int err;
	struct kvm_ops *kvm_ops = vcpu->kvm->arch.kvm_ops;

	err = kvm_ops->vcpu_init(vcpu);
	if (err)
		return err;

	hrtimer_init(&vcpu->arch.swtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	vcpu->arch.swtimer.function = kvm_swtimer_wakeup;
	return 0;
}

void kvm_arch_vcpu_uninit(struct kvm_vcpu *vcpu)
{
	struct kvm_ops *kvm_ops = vcpu->kvm->arch.kvm_ops;

	kvm_ops->vcpu_uninit(vcpu);
}

int kvm_arch_vcpu_ioctl_translate(struct kvm_vcpu *vcpu,
				  struct kvm_translation *tr)
{
	return 0;
}

/* Initial guest state */
int kvm_arch_vcpu_setup(struct kvm_vcpu *vcpu)
{
	struct kvm_ops *kvm_ops = vcpu->kvm->arch.kvm_ops;

	return kvm_ops->vcpu_setup(vcpu);
}

extern exit_handle_fn lvz_exit_handlers[];
/*
 * Return value is in the form (errcode<<2 | RESUME_FLAG_HOST | RESUME_FLAG_NV)
 */
int kvm_loongarch_handle_exit(struct kvm_run *run, struct kvm_vcpu *vcpu)
{
	unsigned long exst = vcpu->arch.host_estat;
	u32 intr = exst & 0x1fff; /* ignore NMI */
	u32 exccode = (exst & CSR_ESTAT_EXC) >> CSR_ESTAT_EXC_SHIFT;
	u32 __user *opc = (u32 __user *) vcpu->arch.pc;
	enum emulation_result er = EMULATE_DONE;
	int ret = RESUME_GUEST;
	struct kvm_ops *kvm_ops = vcpu->kvm->arch.kvm_ops;

	vcpu->mode = OUTSIDE_GUEST_MODE;

	/* Set a default exit reason */
	run->exit_reason = KVM_EXIT_UNKNOWN;
	run->ready_for_interrupt_injection = 1;

	/*
	 * Set the appropriate status bits based on host CPU features,
	 * before we hit the scheduler
	 */

	if (intr) {
		u32 intr_masked = intr & 0x13f;
		if (intr_masked) {
			u32 vector = find_first_bit((void *)&intr_masked, 13);
			do_vi(vector);
		}
	}

	local_irq_enable();

	kvm_debug("kvm_loongarch_handle_exit: exst: %lx, PC: %p, kvm_run: %p, kvm_vcpu: %p\n",
			exst, opc, run, vcpu);
	trace_kvm_exit(vcpu, exccode);

	if (intr) {
		kvm_debug("[%d]EXCCODE_INT @ %p\n", vcpu->vcpu_id, opc);

		++vcpu->stat.int_exits;

		if (need_resched())
			cond_resched();

		ret = RESUME_GUEST;
	} else {
		vcpu->stat.excep_exits[exccode]++;
		ret = lvz_exit_handlers[exccode](vcpu);
	}

#ifdef CONFIG_PARAVIRT
	if (kvm_check_request(KVM_REQ_RECORD_STEAL, vcpu))
		kvm_update_stolen_time(vcpu);
#endif

	cond_resched();

	local_irq_disable();

	if (ret == RESUME_GUEST)
		kvm_acquire_timer(vcpu);

	if (er == EMULATE_DONE && !(ret & RESUME_HOST))
		kvm_loongarch_deliver_interrupts(vcpu);

	if (!(ret & RESUME_HOST)) {
		/* Only check for signals if not already exiting to userspace */
		if (signal_pending(current)) {
			run->exit_reason = KVM_EXIT_INTR;
			ret = (-EINTR << 2) | RESUME_HOST;
			++vcpu->stat.signal_exits;
			trace_kvm_exit(vcpu, KVM_TRACE_EXIT_SIGNAL);
		}
	}

	if (ret == RESUME_GUEST) {
		trace_kvm_reenter(vcpu);

		/*
		 * Make sure the read of VCPU requests in vcpu_reenter()
		 * callback is not reordered ahead of the write to vcpu->mode,
		 * or we could miss a TLB flush request while the requester sees
		 * the VCPU as outside of guest mode and not needing an IPI.
		 */
		smp_store_mb(vcpu->mode, IN_GUEST_MODE);

		kvm_ops->vcpu_reenter(run, vcpu);

		/*
		 * If FPU / LSX are enabled (i.e. the guest's FPU / LSX context
		 * is live), restore FCSR0.
		 */
		if (kvm_loongarch_guest_has_fpu(&vcpu->arch) &&
		    read_csr_euen() & (CSR_EUEN_FPEN | CSR_EUEN_LSXEN)) {
			kvm_restore_fcsr(vcpu);
		}

		if (kvm_loongarch_guest_has_lsx(&vcpu->arch) &&
		    read_csr_euen() & CSR_EUEN_LSXEN)
			kvm_restore_vcsr(vcpu);
	}

	return ret;
}

/* Enable FPU for guest and restore context */
void kvm_own_fpu(struct kvm_vcpu *vcpu)
{
	unsigned long sr;

	preempt_disable();

	sr = kvm_read_hw_gcsr(LOONGARCH_CSR_EUEN);

	/*
	 * If LSX state is already live, it is undefined how it interacts with
	 * FR=0 FPU state, and we don't want to hit reserved instruction
	 * exceptions trying to save the LSX state later when CU=1 && FR=1, so
	 * play it safe and save it first.
	 *
	 * In theory we shouldn't ever hit this case since kvm_lose_fpu() should
	 * get called when guest CU1 is set, however we can't trust the guest
	 * not to clobber the status register directly via the commpage.
	 */
	if (cpu_has_lsx && sr & CSR_EUEN_FPEN &&
	    vcpu->arch.aux_inuse & (KVM_LARCH_LSX | KVM_LARCH_LASX))
		kvm_lose_fpu(vcpu);

	/*
	 * Enable FPU for guest
	 * We set FR and FRE according to guest context
	 */
	set_csr_euen(CSR_EUEN_FPEN);

	/* If guest FPU state not active, restore it now */
	if (!(vcpu->arch.aux_inuse & KVM_LARCH_FPU)) {
		kvm_restore_fpu(vcpu);
		vcpu->arch.aux_inuse |= KVM_LARCH_FPU;
		trace_kvm_aux(vcpu, KVM_TRACE_AUX_RESTORE, KVM_TRACE_AUX_FPU);
	} else {
		trace_kvm_aux(vcpu, KVM_TRACE_AUX_ENABLE, KVM_TRACE_AUX_FPU);
	}

	preempt_enable();
}

#ifdef CONFIG_CPU_HAS_LSX
/* Enable LSX for guest and restore context */
void kvm_own_lsx(struct kvm_vcpu *vcpu)
{
	preempt_disable();

	/*
	 * Enable FP if enabled in guest, since we're restoring FP context
	 * anyway.
	 */
	if (kvm_loongarch_guest_has_fpu(&vcpu->arch)) {

		set_csr_euen(CSR_EUEN_FPEN);
	}

	/* Enable LSX for guest */
	set_csr_euen(CSR_EUEN_LSXEN);

	switch (vcpu->arch.aux_inuse & (KVM_LARCH_FPU |
			 KVM_LARCH_LSX | KVM_LARCH_LASX)) {
		case KVM_LARCH_FPU:
			/*
			 * Guest FPU state already loaded,
			 * only restore upper LSX state
			 */
			kvm_restore_lsx_upper(vcpu);
			vcpu->arch.aux_inuse |= KVM_LARCH_LSX;
			trace_kvm_aux(vcpu, KVM_TRACE_AUX_RESTORE,
						KVM_TRACE_AUX_LSX);
			break;
		case 0:
			/* Neither FP or LSX already active,
			 * restore full LSX state
			 */
			kvm_restore_lsx(vcpu);
			vcpu->arch.aux_inuse |= KVM_LARCH_LSX;
			if (kvm_loongarch_guest_has_fpu(&vcpu->arch))
				vcpu->arch.aux_inuse |= KVM_LARCH_FPU;
			trace_kvm_aux(vcpu, KVM_TRACE_AUX_RESTORE,
					KVM_TRACE_AUX_FPU_LSX);
		break;
	default:
		trace_kvm_aux(vcpu, KVM_TRACE_AUX_ENABLE, KVM_TRACE_AUX_LSX);
		break;
	}

	preempt_enable();
}
#endif

#ifdef CONFIG_CPU_HAS_LASX
/* Enable LASX for guest and restore context */
void kvm_own_lasx(struct kvm_vcpu *vcpu)
{
	preempt_disable();

	/*
	 * Enable FP if enabled in guest, since we're restoring FP context
	 * anyway.
	 */
	if (kvm_loongarch_guest_has_lsx(&vcpu->arch)) {
		/* Enable LSX for guest */
		set_csr_euen(CSR_EUEN_LSXEN);
	}

	/*
	 * Enable FPU if enabled in guest, since we're restoring FPU context
	 * anyway. We set FR and FRE according to guest context.
	 */
	if (kvm_loongarch_guest_has_fpu(&vcpu->arch)) {
		set_csr_euen(CSR_EUEN_FPEN);
	}

	/* Enable LASX for guest */
	set_csr_euen(CSR_EUEN_LASXEN);

	switch (vcpu->arch.aux_inuse & (KVM_LARCH_FPU |
			 KVM_LARCH_LSX | KVM_LARCH_LASX)) {
	case (KVM_LARCH_LSX | KVM_LARCH_FPU):
	case KVM_LARCH_LSX:
		/*
		 * Guest LSX state already loaded, only restore upper LASX state
		 */
		kvm_restore_lasx_upper(vcpu);
		vcpu->arch.aux_inuse |= KVM_LARCH_LASX;
		trace_kvm_aux(vcpu, KVM_TRACE_AUX_RESTORE, KVM_TRACE_AUX_LASX);
		break;
	case KVM_LARCH_FPU:
		/*
		 * Guest FP state already loaded, only restore 64~256 LASX state
		 */
		kvm_restore_lsx_upper(vcpu);
		kvm_restore_lasx_upper(vcpu);
		vcpu->arch.aux_inuse |= KVM_LARCH_LASX;
		if (kvm_loongarch_guest_has_lsx(&vcpu->arch))
			vcpu->arch.aux_inuse |= KVM_LARCH_LSX;
		trace_kvm_aux(vcpu, KVM_TRACE_AUX_RESTORE, KVM_TRACE_AUX_LASX);
		break;
	case 0:
		/* Neither FP or LSX already active, restore full LASX state */
		kvm_restore_lasx(vcpu);
		vcpu->arch.aux_inuse |= KVM_LARCH_LASX;
		if (kvm_loongarch_guest_has_lsx(&vcpu->arch))
			vcpu->arch.aux_inuse |= KVM_LARCH_LSX;
		if (kvm_loongarch_guest_has_fpu(&vcpu->arch))
			vcpu->arch.aux_inuse |= KVM_LARCH_FPU;
		trace_kvm_aux(vcpu, KVM_TRACE_AUX_RESTORE,
			      KVM_TRACE_AUX_FPU_LSX_LASX);
		break;
	default:
		trace_kvm_aux(vcpu, KVM_TRACE_AUX_ENABLE, KVM_TRACE_AUX_LASX);
		break;
	}

	preempt_enable();
}
#endif

/* Save and disable FPU & LSX & LASX */
void kvm_lose_fpu(struct kvm_vcpu *vcpu)
{
	/*
	 * With T&E, FPU & LSX & LASX get disabled in root context (hardware) when it
	 * is disabled in guest context (software), but the register state in
	 * the hardware may still be in use.
	 * This is why we explicitly re-enable the hardware before saving.
	 */

	preempt_disable();
	if (cpu_has_lasx && (vcpu->arch.aux_inuse & KVM_LARCH_LASX)) {

		kvm_save_lasx(vcpu);
		trace_kvm_aux(vcpu, KVM_TRACE_AUX_SAVE, KVM_TRACE_AUX_FPU_LSX_LASX);

		/* Disable LASX & MAS & FPU */
		disable_lasx();
		disable_lsx();

		if (vcpu->arch.aux_inuse & KVM_LARCH_FPU) {
			clear_csr_euen(CSR_EUEN_FPEN);
		}
		vcpu->arch.aux_inuse &= ~(KVM_LARCH_FPU |
					 KVM_LARCH_LSX | KVM_LARCH_LASX);
	} else if (cpu_has_lsx && vcpu->arch.aux_inuse & KVM_LARCH_LSX) {

		kvm_save_lsx(vcpu);
		trace_kvm_aux(vcpu, KVM_TRACE_AUX_SAVE, KVM_TRACE_AUX_FPU_LSX);

		/* Disable LSX & FPU */
		disable_lsx();
		if (vcpu->arch.aux_inuse & KVM_LARCH_FPU) {
			clear_csr_euen(CSR_EUEN_FPEN);
		}
		vcpu->arch.aux_inuse &= ~(KVM_LARCH_FPU | KVM_LARCH_LSX);
	} else if (vcpu->arch.aux_inuse & KVM_LARCH_FPU) {

		kvm_save_fpu(vcpu);
		vcpu->arch.aux_inuse &= ~KVM_LARCH_FPU;
		trace_kvm_aux(vcpu, KVM_TRACE_AUX_SAVE, KVM_TRACE_AUX_FPU);

		/* Disable FPU */
		clear_csr_euen(CSR_EUEN_FPEN);
	}
	preempt_enable();
}

void kvm_lose_hw_breakpoint(struct kvm_vcpu *vcpu)
{
	struct loongarch_csrs *csr = vcpu->arch.csr;

	if (vcpu->arch.aux_inuse & KVM_LARCH_DATA_HWBP) {
		kvm_save_data_hwbp(csr);
		disable_data_hwbp();
	}

	if (vcpu->arch.aux_inuse & KVM_LARCH_INST_HWBP) {
		kvm_save_inst_hwbp(csr);
		disable_inst_hwbp();
	}
}

void kvm_restore_hw_breakpoint(struct kvm_vcpu *vcpu)
{
	struct loongarch_csrs *csr = vcpu->arch.csr;

	if (vcpu->arch.aux_inuse & KVM_LARCH_DATA_HWBP) {
		enable_data_hwbp();
		kvm_restore_data_hwbp(csr);
	}

	if (vcpu->arch.aux_inuse & KVM_LARCH_INST_HWBP) {
		enable_inst_hwbp();
		kvm_restore_inst_hwbp(csr);
	}
}

void kvm_lose_hw_perf(struct kvm_vcpu *vcpu)
{
	if (vcpu->arch.aux_inuse & KVM_LARCH_PERF) {
		struct loongarch_csrs *csr = vcpu->arch.csr;
		/* save guest pmu csr */
		kvm_save_hw_gcsr(csr, LOONGARCH_CSR_PERFCTRL0);
		kvm_save_hw_gcsr(csr, LOONGARCH_CSR_PERFCNTR0);
		kvm_save_hw_gcsr(csr, LOONGARCH_CSR_PERFCTRL1);
		kvm_save_hw_gcsr(csr, LOONGARCH_CSR_PERFCNTR1);
		kvm_save_hw_gcsr(csr, LOONGARCH_CSR_PERFCTRL2);
		kvm_save_hw_gcsr(csr, LOONGARCH_CSR_PERFCNTR2);
		kvm_save_hw_gcsr(csr, LOONGARCH_CSR_PERFCTRL3);
		kvm_save_hw_gcsr(csr, LOONGARCH_CSR_PERFCNTR3);
		/* restore host pmu csr */
		write_csr_gcfg(read_csr_gcfg() & ~CSR_GCFG_GPERF);
		write_csr_perfctrl0(vcpu->arch.perf_ctrl[0]);
		write_csr_perfcntr0(vcpu->arch.perf_cntr[0]);
		write_csr_perfctrl1(vcpu->arch.perf_ctrl[1]);
		write_csr_perfcntr1(vcpu->arch.perf_cntr[1]);
		write_csr_perfctrl2(vcpu->arch.perf_ctrl[2]);
		write_csr_perfcntr2(vcpu->arch.perf_cntr[2]);
		write_csr_perfctrl3(vcpu->arch.perf_ctrl[3]);
		write_csr_perfcntr3(vcpu->arch.perf_cntr[3]);
	}
}

void kvm_restore_hw_perf(struct kvm_vcpu *vcpu)
{
	if (vcpu->arch.aux_inuse & KVM_LARCH_PERF) {
		struct loongarch_csrs *csr = vcpu->arch.csr;
		/* save host pmu csr */
		vcpu->arch.perf_ctrl[0] = read_csr_perfctrl0();
		vcpu->arch.perf_cntr[0] = read_csr_perfcntr0();
		vcpu->arch.perf_ctrl[1] = read_csr_perfctrl1();
		vcpu->arch.perf_cntr[1] = read_csr_perfcntr1();
		vcpu->arch.perf_ctrl[2] = read_csr_perfctrl2();
		vcpu->arch.perf_cntr[2] = read_csr_perfcntr2();
		vcpu->arch.perf_ctrl[3] = read_csr_perfctrl3();
		vcpu->arch.perf_cntr[3] = read_csr_perfcntr3();
		/* enable guest pmu */
		write_csr_gcfg(read_csr_gcfg() | CSR_GCFG_GPERF);
		kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_PERFCTRL0);
		kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_PERFCNTR0);
		kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_PERFCTRL1);
		kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_PERFCNTR1);
		kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_PERFCTRL2);
		kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_PERFCNTR2);
		kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_PERFCTRL3);
		kvm_restore_hw_gcsr(csr, LOONGARCH_CSR_PERFCNTR3);
	}
}

static int __init kvm_loongarch_init(void)
{
	int ret;

	if (!cpu_has_lvz)
		return  0;

	ret = kvm_init(NULL, sizeof(struct kvm_vcpu), 0, THIS_MODULE);

	if (ret)
		return ret;

	return 0;
}

static void __exit kvm_loongarch_exit(void)
{
	kvm_exit();
}

module_init(kvm_loongarch_init);
module_exit(kvm_loongarch_exit);

static const struct cpu_feature loongarch_kvm_feature[] = {
	{ .feature = cpu_feature(LOONGARCH_LVZ) },
	{},
};
MODULE_DEVICE_TABLE(cpu, loongarch_kvm_feature);

EXPORT_TRACEPOINT_SYMBOL(kvm_exit);
