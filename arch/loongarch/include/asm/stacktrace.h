/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 Loongson Technology Co., Ltd.
 */
#ifndef _ASM_STACKTRACE_H
#define _ASM_STACKTRACE_H

#include <asm/ptrace.h>
#include <asm/asm.h>
#include <asm/loongarchregs.h>
#include <linux/stringify.h>

enum stack_type {
	STACK_TYPE_UNKNOWN,
	STACK_TYPE_TASK,
	STACK_TYPE_IRQ,
};

struct stack_info {
	enum stack_type type;
	unsigned long begin, end, next_sp;
};

bool in_task_stack(unsigned long stack, struct task_struct *task,
			struct stack_info *info);
bool in_irq_stack(unsigned long stack, struct stack_info *info);
int get_stack_info(unsigned long stack, struct task_struct *task,
		   struct stack_info *info);

#define STR_LONG_S    __stringify(LONG_S)
#define STR_LONG_L    __stringify(LONG_L)
#define STR_LONGSIZE  __stringify(LONGSIZE)

#define STORE_ONE_REG(r) \
    STR_LONG_S   " $r" __stringify(r)", %1, "STR_LONGSIZE"*"__stringify(r)"\n\t"

#define CSRRD_ONE_REG(csr_reg) \
    __stringify(csrrd) " %0, "__stringify(csr_reg)"\n\t"

static __always_inline void prepare_frametrace(struct pt_regs *regs)
{
	__asm__ __volatile__(
		/* Save $r1 */
		STORE_ONE_REG(1)
		/* Use $r1 to save pc to pt_regs->csr_era*/
		"pcaddi	$r1, 0\n\t"
		STR_LONG_S " $r1, %0\n\t"
		/* Restore $r1 */
		STR_LONG_L " $r1, %1, "STR_LONGSIZE"\n\t"
		STORE_ONE_REG(2)
		STORE_ONE_REG(3)
		STORE_ONE_REG(4)
		STORE_ONE_REG(5)
		STORE_ONE_REG(6)
		STORE_ONE_REG(7)
		STORE_ONE_REG(8)
		STORE_ONE_REG(9)
		STORE_ONE_REG(10)
		STORE_ONE_REG(11)
		STORE_ONE_REG(12)
		STORE_ONE_REG(13)
		STORE_ONE_REG(14)
		STORE_ONE_REG(15)
		STORE_ONE_REG(16)
		STORE_ONE_REG(17)
		STORE_ONE_REG(18)
		STORE_ONE_REG(19)
		STORE_ONE_REG(20)
		STORE_ONE_REG(21)
		STORE_ONE_REG(22)
		STORE_ONE_REG(23)
		STORE_ONE_REG(24)
		STORE_ONE_REG(25)
		STORE_ONE_REG(26)
		STORE_ONE_REG(27)
		STORE_ONE_REG(28)
		STORE_ONE_REG(29)
		STORE_ONE_REG(30)
		STORE_ONE_REG(31)
		: "=m" (regs->csr_era)
		: "r" (regs->regs)
		: "memory");
	__asm__ __volatile__(CSRRD_ONE_REG(LOONGARCH_CSR_BADV) : "=r" (regs->csr_badv));
	__asm__ __volatile__(CSRRD_ONE_REG(LOONGARCH_CSR_CRMD) : "=r" (regs->csr_crmd));
	__asm__ __volatile__(CSRRD_ONE_REG(LOONGARCH_CSR_PRMD) : "=r" (regs->csr_prmd));
	__asm__ __volatile__(CSRRD_ONE_REG(LOONGARCH_CSR_EUEN) : "=r" (regs->csr_euen));
	__asm__ __volatile__(CSRRD_ONE_REG(LOONGARCH_CSR_ECFG) : "=r" (regs->csr_ecfg));
	__asm__ __volatile__(CSRRD_ONE_REG(LOONGARCH_CSR_ESTAT) : "=r" (regs->csr_estat));
}

#endif /* _ASM_STACKTRACE_H */
