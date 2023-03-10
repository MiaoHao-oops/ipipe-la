/* SPDX-License-Identifier: GPL-2.0+ */
/*
* Copyright (C) 2020 Loongson Technology Corporation Limited
*
* Author: Hanlu Li <lihanlu@loongson.cn>
*/

#ifndef __SIGNAL_COMMON_H
#define __SIGNAL_COMMON_H

#include <asm/ipipe_hwirq.h>

/* #define DEBUG_SIG */

#ifdef DEBUG_SIG
#  define DEBUGP(fmt, args...) printk("%s: " fmt, __func__, ##args)
#else
#  define DEBUGP(fmt, args...)
#endif

/*
 * Determine which stack to use..
 */
extern void __user *get_sigframe(struct ksignal *ksig, struct pt_regs *regs,
				 size_t frame_size);
/* Check and clear pending FPU exceptions in saved CSR */
extern int fpcsr_pending(unsigned int __user *fpcsr);

/* Make sure we will not lose FPU ownership */
#ifdef CONFIG_IPIPE
#define lock_fpu_owner()		\
({					\
	unsigned long flags;		\
	flags = hard_local_irq_save();	\
	pagefault_disable();		\
	flags;				\
})
#define unlock_fpu_owner(flags)		\
({					\
	pagefault_enable();		\
	hard_local_irq_restore(flags);	\
})
#else
#define lock_fpu_owner()	({ preempt_disable(); pagefault_disable(); 0; })
#define unlock_fpu_owner(flags)	({ pagefault_enable(); preempt_enable(); })
#endif

/* Assembly functions to move context to/from the FPU */
extern asmlinkage int
_save_fp_context(void __user *fpregs, void __user *fcc, void __user *csr);
extern asmlinkage int
_restore_fp_context(void __user *fpregs, void __user *fcc, void __user *csr);
extern asmlinkage int
_save_lsx_context(void __user *fpregs, void __user *fcc, void __user *fcsr,
	void __user *vcsr);
extern asmlinkage int
_restore_lsx_context(void __user *fpregs, void __user *fcc, void __user *fcsr,
	void __user *vcsr);
extern asmlinkage int
_save_lasx_context(void __user *fpregs, void __user *fcc, void __user *fcsr,
	void __user *vcsr);
extern asmlinkage int
_restore_lasx_context(void __user *fpregs, void __user *fcc, void __user *fcsr,
	void __user *vcsr);
#if defined(CONFIG_CPU_HAS_LBT)
extern asmlinkage int
_save_scr_context(void __user *scr, void __user *eflags);
extern asmlinkage int
_restore_scr_context(void __user *scr, void __user *eflags);
#endif
extern asmlinkage int _save_lsx_all_upper(void __user *buf);
extern asmlinkage int _restore_lsx_all_upper(void __user *buf);

#endif	/* __SIGNAL_COMMON_H */
