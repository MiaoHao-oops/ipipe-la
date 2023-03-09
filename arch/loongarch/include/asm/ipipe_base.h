/* -*- linux-c -*-
 * arch/loongarch/include/asm/ipipe_base.h
 *
 * Copyright (C) 2007 Gilles Chanteperdrix.
 * Copyright (C) 2010 Philippe Gerum (SMP port).
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 * USA; either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef __ASM_LOONGARCH_IPIPE_BASE_H
#define __ASM_LOONGARCH_IPIPE_BASE_H

#include <asm/ipipe_hwirq.h>
#include <asm-generic/ipipe.h>

#ifdef CONFIG_IPIPE

#include <asm/hardirq.h>

#define IPIPE_NR_ROOT_IRQS	NR_IRQS

#define IPIPE_NR_XIRQS		IPIPE_NR_ROOT_IRQS

#ifdef CONFIG_SMP
/*
 * Out-of-band IPIs are directly mapped to reserved action bits,
 * just like regular in-band IPI requests.
 */
#define IPIPE_IPI_BASE         IPIPE_VIRQ_BASE
#define IPIPE_OOB_IPI_NR	4
#define IPIPE_CRITICAL_IPI     (IPIPE_IPI_BASE + NR_IPI)
#define IPIPE_HRTIMER_IPI      (IPIPE_IPI_BASE + NR_IPI + 1)
#define IPIPE_RESCHEDULE_IPI   (IPIPE_IPI_BASE + NR_IPI + 2)
#define IPIPE_SERVICE_VNMI   (IPIPE_IPI_BASE + NR_IPI + 3)

#define hard_smp_processor_id()	raw_smp_processor_id()
#define ipipe_processor_id() raw_smp_processor_id()

#define IPIPE_ARCH_HAVE_VIRQ_IPI

#else /* !CONFIG_SMP */
#define ipipe_processor_id()  (0)
#endif /* !CONFIG_SMP */

/* LoongArch64 traps */
#define IPIPE_TRAP_MAYDAY        0	/* Internal recovery trap */
#define IPIPE_TRAP_ACCESS	 1	/* Data or instruction access exception */
#define IPIPE_TRAP_SECTION	 2	/* Section fault */
#define IPIPE_TRAP_DABT		 3	/* Generic data abort */
#define IPIPE_TRAP_UNKNOWN	 4	/* Unknown exception */
#define IPIPE_TRAP_BREAK	 5	/* Instruction breakpoint */
#define IPIPE_TRAP_FPU_ACC	 6	/* Floating point access */
#define IPIPE_TRAP_LSX_ACC	 7	/* LSX access */
#define IPIPE_TRAP_LASX_ACC	 8	/* LASX access */
#define IPIPE_TRAP_FPU_EXC	 9	/* Floating point exception */
#define IPIPE_TRAP_RI		 10	/* Reserved instruction */
#define IPIPE_TRAP_ALIGNMENT	 11	/* Unaligned access exception */
#define IPIPE_NR_FAULTS         12

#endif /* CONFIG_IPIPE */

#endif /* __ASM_LOONGARCH_IPIPE_BASE_H */
