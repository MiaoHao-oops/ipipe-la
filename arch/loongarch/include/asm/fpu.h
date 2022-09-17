/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2002 MontaVista Software Inc.
 * Author: Jun Sun, jsun@mvista.com or jsun@junsun.net
 * Copyright (C) 2020 Loongson Technology Corporation Limited
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */
#ifndef _ASM_FPU_H
#define _ASM_FPU_H

#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <linux/ptrace.h>
#include <linux/thread_info.h>
#include <linux/bitops.h>

#include <asm/cpu.h>
#include <asm/cpu-features.h>
#include <asm/current.h>
#include <asm/inst.h>
#include <asm/loongarchregs.h>
#include <asm/ptrace.h>
#include <asm/processor.h>

struct sigcontext;

extern void _init_fpu(unsigned int);
extern void _save_fp(struct loongarch_fpu *);
extern void _restore_fp(struct loongarch_fpu *);

extern void _save_lsx(struct loongarch_fpu *fpu);
extern void _restore_lsx(struct loongarch_fpu *fpu);
extern void _init_lsx_upper(void);
extern void _restore_lsx_upper(struct loongarch_fpu *fpu);

extern void _save_lasx(struct loongarch_fpu *fpu);
extern void _restore_lasx(struct loongarch_fpu *fpu);
extern void _init_lasx_upper(void);
extern void _restore_lasx_upper(struct loongarch_fpu *fpu);

static inline void enable_lsx(void);
static inline void disable_lsx(void);
static inline void save_lsx(struct task_struct *t);
static inline void restore_lsx(struct task_struct *t);

static inline void enable_lasx(void);
static inline void disable_lasx(void);
static inline void save_lasx(struct task_struct *t);
static inline void restore_lasx(struct task_struct *t);

#ifdef CONFIG_LOONGSON3_ACPI_CPUFREQ
DECLARE_PER_CPU(unsigned long, msa_count);
DECLARE_PER_CPU(unsigned long, lasx_count);
#endif

/*
 * Mask the FCSR Cause bits according to the Enable bits, observing
 * that Unimplemented is always enabled.
 */
static inline unsigned long mask_fcsr_x(unsigned long fcsr)
{
	return fcsr & ((fcsr & FPU_CSR_ALL_E) <<
			(ffs(FPU_CSR_ALL_X) - ffs(FPU_CSR_ALL_E)));
}

static inline int is_fp_enabled(void)
{
	return (csr_readl(LOONGARCH_CSR_EUEN) & CSR_EUEN_FPEN) ?
		1 : 0;
}

static inline int is_lsx_enabled(void)
{
	if (!cpu_has_lsx)
		return 0;

	return (csr_readl(LOONGARCH_CSR_EUEN) & CSR_EUEN_LSXEN) ?
		1 : 0;
}

static inline int is_lasx_enabled(void)
{
	if (!cpu_has_lasx)
		return 0;

	return (csr_readl(LOONGARCH_CSR_EUEN) & CSR_EUEN_LASXEN) ?
		1 : 0;
}

static inline int is_simd_enabled(void)
{
	return is_lsx_enabled() | is_lasx_enabled();
}

#define enable_fpu()						\
do {								\
	set_csr_euen(CSR_EUEN_FPEN);				\
} while (0)

#define disable_fpu()						\
do {								\
	clear_csr_euen(CSR_EUEN_FPEN);				\
} while (0)

#define clear_fpu_owner()	clear_thread_flag(TIF_USEDFPU)

static inline int is_fpu_owner(void)
{
	return test_thread_flag(TIF_USEDFPU);
}

static inline void __own_fpu(void)
{
	enable_fpu();
	set_thread_flag(TIF_USEDFPU);
	KSTK_EUEN(current) |= CSR_EUEN_FPEN;
}

static inline void own_fpu_inatomic(int restore)
{
	if (cpu_has_fpu && !is_fpu_owner()) {
		__own_fpu();
		if (restore)
			_restore_fp(&current->thread.fpu);
	}
}

static inline void own_fpu(int restore)
{
	preempt_disable();
	own_fpu_inatomic(restore);
	preempt_enable();
}

static inline void lose_fpu_inatomic(int save, struct task_struct *tsk)
{
	if (is_fpu_owner()) {
		if (is_simd_enabled()) {
			if (save) {
				if (is_lasx_enabled())
					save_lasx(tsk);
				else
					save_lsx(tsk);
			}
			disable_lsx();
			clear_tsk_thread_flag(tsk, TIF_USEDSIMD);
			disable_fpu();
			disable_lasx();
		} else {
			if (save)
				_save_fp(&tsk->thread.fpu);
			disable_fpu();
		}
		clear_tsk_thread_flag(tsk, TIF_USEDFPU);
	}
	KSTK_EUEN(tsk) &= ~(CSR_EUEN_FPEN | CSR_EUEN_LSXEN | CSR_EUEN_LASXEN);
}

static inline void lose_fpu(int save)
{
	preempt_disable();
	lose_fpu_inatomic(save, current);
	preempt_enable();
}

static inline void init_fpu(void)
{
	unsigned int fcsr = current->thread.fpu.fcsr;

	__own_fpu();
	_init_fpu(fcsr);
	set_used_math();
}

static inline void save_fp(struct task_struct *tsk)
{
	if (cpu_has_fpu)
		_save_fp(&tsk->thread.fpu);
}

static inline void restore_fp(struct task_struct *tsk)
{
	if (cpu_has_fpu)
		_restore_fp(&tsk->thread.fpu);
}

static inline union fpureg *get_fpu_regs(struct task_struct *tsk)
{
	if (tsk == current) {
		preempt_disable();
		if (is_fpu_owner())
			_save_fp(&current->thread.fpu);
		preempt_enable();
	}

	return tsk->thread.fpu.fpr;
}

enum {
	CTX_LSX = 1,
	CTX_LASX = 2,
};

static inline int is_simd_owner(void)
{
	return test_thread_flag(TIF_USEDSIMD);
}

#ifdef CONFIG_CPU_HAS_LSX

static inline void enable_lsx(void)
{
	if (cpu_has_lsx) {
		csr_xchgl(CSR_EUEN_LSXEN, CSR_EUEN_LSXEN, LOONGARCH_CSR_EUEN);
#ifdef CONFIG_LOONGSON3_ACPI_CPUFREQ
		per_cpu(msa_count, raw_smp_processor_id())++;
#endif
	}
}

static inline void disable_lsx(void)
{
	if (cpu_has_lsx)
		csr_xchgl(0, CSR_EUEN_LSXEN, LOONGARCH_CSR_EUEN);
}

static inline void save_lsx(struct task_struct *t)
{
	if (cpu_has_lsx)
		_save_lsx(&t->thread.fpu);
}

static inline void restore_lsx(struct task_struct *t)
{
	if (cpu_has_lsx)
		_restore_lsx(&t->thread.fpu);
}

static inline void init_lsx_upper(void)
{
	/*
	 * Check cpu_has_lsx only if it's a constant. This will allow the
	 * compiler to optimise out code for CPUs without LSX without adding
	 * an extra redundant check for CPUs with LSX.
	 */
	if (__builtin_constant_p(cpu_has_lsx) && !cpu_has_lsx)
		return;

	_init_lsx_upper();
}

static inline void restore_lsx_upper(struct task_struct *t)
{
	if (cpu_has_lsx)
		_restore_lsx_upper(&t->thread.fpu);
}

#else
static inline void enable_lsx(void) {}
static inline void disable_lsx(void) {}
static inline void save_lsx(struct task_struct *t) {}
static inline void restore_lsx(struct task_struct *t) {}
static inline void init_lsx_upper(void) {}
static inline void restore_lsx_upper(struct task_struct *t) {}
#endif

#ifdef CONFIG_CPU_HAS_LASX

static inline void enable_lasx(void)
{

	if (cpu_has_lasx) {
		csr_xchgl(CSR_EUEN_LASXEN, CSR_EUEN_LASXEN, LOONGARCH_CSR_EUEN);
#ifdef CONFIG_LOONGSON3_ACPI_CPUFREQ
		per_cpu(lasx_count, raw_smp_processor_id())++;
#endif
	}
}

static inline void disable_lasx(void)
{
	if (cpu_has_lasx)
		csr_xchgl(0, CSR_EUEN_LASXEN, LOONGARCH_CSR_EUEN);
}

static inline void save_lasx(struct task_struct *t)
{
	if (cpu_has_lasx)
		_save_lasx(&t->thread.fpu);
}

static inline void restore_lasx(struct task_struct *t)
{
	if (cpu_has_lasx)
		_restore_lasx(&t->thread.fpu);
}

static inline void init_lasx_upper(void)
{
	if (cpu_has_lasx)
		_init_lasx_upper();
}

static inline void restore_lasx_upper(struct task_struct *t)
{
	if (cpu_has_lasx)
		_restore_lasx_upper(&t->thread.fpu);
}

#else
static inline void enable_lasx(void) {}
static inline void disable_lasx(void) {}
static inline void save_lasx(struct task_struct *t) {}
static inline void restore_lasx(struct task_struct *t) {}
static inline void init_lasx_upper(void) {}
static inline void restore_lasx_upper(struct task_struct *t) {}
#endif

static inline int thread_lsx_context_live(void)
{
	int ret = 0;

	if (__builtin_constant_p(cpu_has_lsx) && !cpu_has_lsx)
		goto  out;

	ret =  test_thread_flag(TIF_LSX_CTX_LIVE) ? CTX_LSX : 0;
out:
	return ret;
}

static inline int thread_lasx_context_live(void)
{
	int ret = 0;

	if (__builtin_constant_p(cpu_has_lasx) && !cpu_has_lasx)
		goto out;

	ret = test_thread_flag(TIF_LASX_CTX_LIVE) ? CTX_LASX : 0;
out:
	return ret;
}

#define __BUILD_VCTL_REG(name, cs)				\
static inline unsigned int read_v##name(void)			\
{								\
	unsigned int reg;					\
	__asm__ __volatile__(					\
	"	movfcsr2gr	%0, $r" #cs "\n"		\
	: "=r"(reg));						\
	return reg;						\
}								\
								\
static inline void write_v##name(unsigned int val)		\
{								\
	__asm__ __volatile__(					\
	"	movgr2fcsr	$r" #cs ", %0\n"		\
	: : "r"(val));						\
}

__BUILD_VCTL_REG(csr0, 0)
__BUILD_VCTL_REG(csr1, 1)
__BUILD_VCTL_REG(csr2, 2)
__BUILD_VCTL_REG(csr3, 3)
__BUILD_VCTL_REG(csr16, 16)

#endif /* _ASM_FPU_H */
