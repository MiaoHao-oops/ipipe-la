// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 Loongson Technology Corporation Limited
 */
#include <linux/context_tracking.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/ratelimit.h>
#include <linux/rwsem.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/kprobes.h>
#include <linux/perf_event.h>
#include <linux/uaccess.h>

#include <asm/branch.h>
#include <asm/mmu_context.h>
#include <asm/ptrace.h>
#include <linux/kdebug.h>

int show_unhandled_signals = 1;

/*
 * This routine handles page faults.  It determines the address,
 * and the problem, and then passes it off to one of the appropriate
 * routines.
 */
static void __kprobes __do_page_fault(struct pt_regs *regs, unsigned long write,
	unsigned long address)
{
	struct vm_area_struct * vma = NULL;
	struct task_struct *tsk = current;
	struct mm_struct *mm = tsk->mm;
	const int field = sizeof(unsigned long) * 2;
	int si_code;
	vm_fault_t fault;
	unsigned int flags = FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_KILLABLE;

	static DEFINE_RATELIMIT_STATE(ratelimit_state, 5 * HZ, 10);

#ifdef CONFIG_KPROBES
	/*
	 * This is to notify the fault handler of the kprobes.
	 */
	if (notify_die(DIE_PAGE_FAULT, "page fault", regs, -1,
		       current->thread.trap_nr, SIGSEGV) == NOTIFY_STOP)
		return;
#endif

	si_code = SEGV_MAPERR;

	/*
	 * We fault-in kernel-space virtual memory on-demand. The
	 * 'reference' page table is init_mm.pgd.
	 *
	 * NOTE! We MUST NOT take any locks for this case. We may
	 * be in an interrupt or a critical region, and should
	 * only copy the information from the master page table,
	 * nothing more.
	 */
#ifdef CONFIG_64BIT
# define VMALLOC_FAULT_TARGET no_context
#else
# define VMALLOC_FAULT_TARGET vmalloc_fault
#endif
	printk("[0]prmd: 0x%lx", regs->csr_prmd);
	if (user_mode(regs) && (get_fs().seg & address))
		goto bad_area_nosemaphore;

	if (unlikely(address >= VMALLOC_START && address <= VMALLOC_END))
		goto VMALLOC_FAULT_TARGET;

	/*
	 * If we're in an interrupt or have no user
	 * context, we must not take the fault..
	 */
	if (faulthandler_disabled() || !mm)
		goto bad_area_nosemaphore;

	if (user_mode(regs))
		flags |= FAULT_FLAG_USER;
retry:
	down_read(&mm->mmap_sem);
	vma = find_vma(mm, address);
	if (!vma)
		goto bad_area;
	if (vma->vm_start <= address)
		goto good_area;
	if (!(vma->vm_flags & VM_GROWSDOWN))
		goto bad_area;
	if (expand_stack(vma, address))
		goto bad_area;
/*
 * Ok, we have a good vm_area for this memory access, so
 * we can handle it..
 */
good_area:
	si_code = SEGV_ACCERR;

	if (write) {
		if (!(vma->vm_flags & VM_WRITE))
			goto bad_area;
		flags |= FAULT_FLAG_WRITE;
	} else {
		if (address == regs->csr_era && !(vma->vm_flags & VM_EXEC))
			goto bad_area;
		if (!(vma->vm_flags & VM_READ) &&
		    exception_era(regs) != address)
			goto bad_area;
	}

	/*
	 * If for any reason at all we couldn't handle the fault,
	 * make sure we exit gracefully rather than endlessly redo
	 * the fault.
	 */
	fault = handle_mm_fault(vma, address, flags);

	if ((fault & VM_FAULT_RETRY) && fatal_signal_pending(current))
		return;

	perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS, 1, regs, address);
	if (unlikely(fault & VM_FAULT_ERROR)) {
		if (fault & VM_FAULT_OOM)
			goto out_of_memory;
		else if (fault & VM_FAULT_SIGSEGV)
			goto bad_area;
		else if (fault & (VM_FAULT_SIGBUS | VM_FAULT_HWPOISON | VM_FAULT_HWPOISON_LARGE))
			goto do_sigbus;
		BUG();
	}
	if (flags & FAULT_FLAG_ALLOW_RETRY) {
		if (fault & VM_FAULT_MAJOR) {
			perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MAJ, 1,
						  regs, address);
			tsk->maj_flt++;
		} else {
			perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MIN, 1,
						  regs, address);
			tsk->min_flt++;
		}
		if (fault & VM_FAULT_RETRY) {
			flags &= ~FAULT_FLAG_ALLOW_RETRY;
			flags |= FAULT_FLAG_TRIED;

			/*
			 * No need to up_read(&mm->mmap_sem) as we would
			 * have already released it in __lock_page_or_retry
			 * in mm/filemap.c.
			 */

			goto retry;
		}
	}

	up_read(&mm->mmap_sem);
	return;

/*
 * Something tried to access memory that isn't in our memory map..
 * Fix it, but check if it's kernel or user first..
 */
bad_area:
	up_read(&mm->mmap_sem);

bad_area_nosemaphore:
	printk("[1]prmd: 0x%lx", regs->csr_prmd);

	/* User mode accesses just cause a SIGSEGV */
	if (user_mode(regs)) {
		tsk->thread.csr_badv = address;
		/*1:read access; 2:write access*/
		if (write)
			tsk->thread.error_code = 2;
		else
			tsk->thread.error_code = 1;
		if (show_unhandled_signals &&
		    unhandled_signal(tsk, SIGSEGV) &&
		    __ratelimit(&ratelimit_state)) {
			pr_info("do_page_fault(): sending SIGSEGV to %s for invalid %s %0*lx\n",
				tsk->comm,
				write ? "write access to" : "read access from",
				field, address);
			pr_info("era = %0*lx in", field,
				(unsigned long) regs->csr_era);
			print_vma_addr(KERN_CONT " ", regs->csr_era);
			pr_cont("\n");
			pr_info("ra  = %0*lx in", field,
				(unsigned long) regs->regs[1]);
			print_vma_addr(KERN_CONT " ", regs->regs[1]);
			pr_cont("\n");
		}
		current->thread.trap_nr = read_csr_excode();
		force_sig_fault(SIGSEGV, si_code, (void __user *)address, tsk);
		return;
	}

no_context:
	/* Are we prepared to handle this kernel fault?	 */
	if (fixup_exception(regs))
		return;

	/*
	 * Oops. The kernel tried to access some bad page. We'll have to
	 * terminate things with extreme prejudice.
	 */
	bust_spinlocks(1);

	printk(KERN_ALERT "CPU %d Unable to handle kernel paging request at "
	       "virtual address %0*lx, era == %0*lx, ra == %0*lx\n",
	       raw_smp_processor_id(), field, address, field, regs->csr_era,
	       field,  regs->regs[1]);
	die("Oops", regs);

out_of_memory:
	/*
	 * We ran out of memory, call the OOM killer, and return the userspace
	 * (which will retry the fault, or kill us if we got oom-killed).
	 */
	up_read(&mm->mmap_sem);
	if (!user_mode(regs))
		goto no_context;
	pagefault_out_of_memory();
	return;

do_sigbus:
	up_read(&mm->mmap_sem);

	/* Kernel mode? Handle exceptions or die */
	if (!user_mode(regs))
		goto no_context;

	/*
	 * Send a sigbus, regardless of whether we were in kernel
	 * or user mode.
	 */
	current->thread.trap_nr = read_csr_excode();
	tsk->thread.csr_badv = address;
	force_sig_fault(SIGBUS, BUS_ADRERR, (void __user *)address, tsk);

	return;

#ifndef CONFIG_64BIT
vmalloc_fault:
	{
		/*
		 * Synchronize this task's top level page-table
		 * with the 'reference' page table.
		 *
		 * Do _not_ use "tsk" here. We might be inside
		 * an interrupt in the middle of a task switch..
		 */
		int offset = __pgd_offset(address);
		pgd_t *pgd, *pgd_k;
		pud_t *pud, *pud_k;
		pmd_t *pmd, *pmd_k;
		pte_t *pte_k;

		pgd = (pgd_t *) pgd_current[raw_smp_processor_id()] + offset;
		pgd_k = init_mm.pgd + offset;

		if (!pgd_present(*pgd_k))
			goto no_context;
		set_pgd(pgd, *pgd_k);

		pud = pud_offset(pgd, address);
		pud_k = pud_offset(pgd_k, address);
		if (!pud_present(*pud_k))
			goto no_context;

		pmd = pmd_offset(pud, address);
		pmd_k = pmd_offset(pud_k, address);
		if (!pmd_present(*pmd_k))
			goto no_context;
		set_pmd(pmd, *pmd_k);

		pte_k = pte_offset_kernel(pmd_k, address);
		if (!pte_present(*pte_k))
			goto no_context;
		return;
	}
#endif
}

#ifdef CONFIG_IPIPE
/*
 * We need to synchronize the virtual interrupt state with the hard
 * interrupt state we received on entry, then turn hardirqs back on to
 * allow code which does not require strict serialization to be
 * preempted by an out-of-band activity.
 *
 * TRACING: the entry code already told lockdep and tracers about the
 * hard interrupt state on entry to fault handlers, so no need to
 * reflect changes to that state via calls to trace_hardirqs_*
 * helpers. From the main kernel's point of view, there is no change.
 */
static inline
unsigned long fault_entry(struct pt_regs *regs)
{
	unsigned long flags;
	int nosync = 1;

	flags = hard_local_irq_save();
	if (irqs_disabled_flags(flags))
		nosync = __test_and_set_bit(IPIPE_STALL_FLAG,
					    &__ipipe_root_status);
	hard_local_irq_enable();

	return arch_mangle_irq_bits(nosync, flags);
}
static inline void fault_exit(unsigned long flags)
{
	int nosync;

	IPIPE_WARN_ONCE(hard_irqs_disabled());

	/*
	 * '!nosync' here means that we had to turn on the stall bit
	 * in fault_entry() to mirror the hard interrupt state,
	 * because hard irqs were off but the stall bit was
	 * clear. Conversely, nosync in fault_exit() means that the
	 * stall bit state currently reflects the hard interrupt state
	 * we received on fault_entry().
	 */
	nosync = arch_demangle_irq_bits(&flags);
	if (!nosync) {
		hard_local_irq_disable();
		__clear_bit(IPIPE_STALL_FLAG, &__ipipe_root_status);
		if (!hard_irqs_disabled_flags(flags))
			hard_local_irq_enable();
	} else if (hard_irqs_disabled_flags(flags))
		hard_local_irq_disable();
}

#else

static inline unsigned long fault_entry(struct pt_regs *regs)
{
	return 0;
}

static inline void fault_exit(unsigned long x) { }
#endif /* !CONFIG_IPIPE */

asmlinkage void __kprobes do_page_fault(struct pt_regs *regs,
	unsigned long write, unsigned long address)
{
	enum ctx_state prev_state;
	unsigned long irqflags;

	if (__ipipe_report_trap(IPIPE_TRAP_ACCESS, regs))
		return;

	irqflags = fault_entry(regs);

	prev_state = exception_enter();
	__do_page_fault(regs, write, address);
	exception_exit(prev_state);

	fault_exit(irqflags);
}
