// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2010, 2011, 2012, Lemote, Inc.
 * Author: Chen Huacai, chenhc@lemote.com
 * Copyright (C) 2020 Loongson Technology Corporation Limited
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/init.h>
#include <linux/cpu.h>
#include <linux/sched.h>
#include <linux/sched/hotplug.h>
#include <linux/sched/task_stack.h>
#include <linux/seq_file.h>
#include <linux/smp.h>
#include <linux/syscore_ops.h>
#include <linux/acpi.h>
#include <linux/tracepoint.h>
#include <asm/processor.h>
#include <asm/time.h>
#include <asm/tlbflush.h>
#include <asm/cacheflush.h>
#include <asm/numa.h>
#include <loongson.h>
#include <asm/delay.h>
#include <loongson-pch.h>

#include "smp.h"
#include <larchintrin.h>

static DEFINE_PER_CPU(int, cpu_state);

#define MAX_CPUS min(64, NR_CPUS)

static u32 (*ipi_read_clear)(int cpu);
static void (*ipi_write_action)(int cpu, u32 action);

enum ipi_msg_type {
	IPI_RESCHEDULE,
	IPI_CALL_FUNC,
};

static const char *ipi_types[NR_IPI] __tracepoint_string = {
	[IPI_RESCHEDULE] = "Rescheduling interrupts",
	[IPI_CALL_FUNC] = "Call Function interrupts",
};

void show_ipi_list(struct seq_file *p, int prec)
{
	unsigned int cpu, i;

	for (i = 0; i < NR_IPI; i++) {
		seq_printf(p, "%*s%u:%s", prec - 1, "IPI", i,
			   prec >= 4 ? " " : "");
		for_each_online_cpu(cpu)
			seq_printf(p, "%10u ",
				   __get_irq_stat(cpu, ipi_irqs[i]));
		seq_printf(p, "      %s\n", ipi_types[i]);
	}
}

/* Send mail buffer via Mail_Send */
static void csr_mail_send(uint64_t data, int cpu, int mailbox)
{
	uint64_t val;

	/* Send high 32 bits */
	val = IOCSR_MBUF_SEND_BLOCKING;
	val |= (IOCSR_MBUF_SEND_BOX_HI(mailbox) << IOCSR_MBUF_SEND_BOX_SHIFT);
	val |= (cpu << IOCSR_MBUF_SEND_CPU_SHIFT);
	val |= (data & IOCSR_MBUF_SEND_H32_MASK);
	iocsr_writeq(val, LOONGARCH_IOCSR_MBUF_SEND);

	/* Send low 32 bits */
	val = IOCSR_MBUF_SEND_BLOCKING;
	val |= (IOCSR_MBUF_SEND_BOX_LO(mailbox) << IOCSR_MBUF_SEND_BOX_SHIFT);
	val |= (cpu << IOCSR_MBUF_SEND_CPU_SHIFT);
	val |= (data << IOCSR_MBUF_SEND_BUF_SHIFT);
	iocsr_writeq(val, LOONGARCH_IOCSR_MBUF_SEND);
};

static u32 csr_ipi_read_clear(int cpu)
{
	u32 action;

	/* Load the ipi register to figure out what we're supposed to do */
	action = iocsr_readl(LOONGARCH_IOCSR_IPI_STATUS);
	/* Clear the ipi register to clear the interrupt */
	iocsr_writel(action, LOONGARCH_IOCSR_IPI_CLEAR);

	return action;
}

static void csr_ipi_write_action(int cpu, u32 action)
{
	unsigned int irq = 0;

	while ((irq = ffs(action))) {
		uint32_t val = IOCSR_IPI_SEND_BLOCKING;
		val |= (irq - 1);
		val |= (cpu << IOCSR_IPI_SEND_CPU_SHIFT);
		iocsr_writel(val, LOONGARCH_IOCSR_IPI_SEND);
		action &= ~BIT(irq - 1);
	}
}

static void ipi_method_init(void)
{
	ipi_read_clear = csr_ipi_read_clear;
	ipi_write_action = csr_ipi_write_action;
}

/*
 * Simple enough, just poke the appropriate ipi register
 */
static void loongson3_send_ipi_single(int cpu, unsigned int action)
{
	ipi_write_action(cpu_logical_map(cpu), (u32)action);
}

static void
loongson3_send_ipi_mask(const struct cpumask *mask, unsigned int action)
{
	unsigned int i;

	for_each_cpu(i, mask)
		ipi_write_action(cpu_logical_map(i), (u32)action);
}

#ifdef CONFIG_IPIPE

static DEFINE_PER_CPU(unsigned long, ipi_messages);

#define noipipe_irq_enter()                    \
       do {                                    \
       } while (0)
#define noipipe_irq_exit()                     \
       do {                                    \
       } while (0)


static void  __ipipe_do_IPI(unsigned int virq, void *cookie)
{
       unsigned int ipinr = virq - IPIPE_IPI_BASE;

       loongson3_ipi_interrupt(ipinr);
}

void __ipipe_ipis_alloc(void)
{
       unsigned int virq, ipi;
       static bool done;

       if (done)
               return;

       /*
        * We have to get virtual IRQs in the range
        * [ IPIPE_IPI_BASE..IPIPE_IPI_BASE + NR_IPI + IPIPE_OOB_IPI_NR - 1 ],
        * otherwise something is wrong (likely someone would have
        * allocated virqs before we do, and this would break our
        * fixed numbering scheme for IPIs).
        */
       for (ipi = 0; ipi < NR_IPI + IPIPE_OOB_IPI_NR; ipi++) {
               virq = ipipe_alloc_virq();
               WARN_ON_ONCE(virq != IPIPE_IPI_BASE + ipi);
       }

       done = true;
}
void __ipipe_ipis_request(void)
{
       unsigned int virq;

       /*
        * Attach a handler to each VIRQ mapping an IPI which might be
        * posted by __ipipe_grab_ipi(). This handler will invoke
        * handle_IPI() from the root stage in turn, passing it the
        * corresponding IPI message number.
        */
       for (virq = IPIPE_IPI_BASE;
            virq < IPIPE_IPI_BASE + NR_IPI + IPIPE_OOB_IPI_NR; virq++)
               ipipe_request_irq(ipipe_root_domain,
                                 virq,
                                 (ipipe_irq_handler_t)__ipipe_do_IPI,
                                 NULL, NULL);
}

static void smp_cross_call(const struct cpumask *target, unsigned int ipinr)
{
       unsigned int cpu, sgi;
       unsigned long flags;

       if (ipinr < NR_IPI) {
               /* regular in-band IPI (multiplexed over SGI0). */
               for_each_cpu(cpu, target)
                       set_bit(ipinr, &per_cpu(ipi_messages, cpu));
               smp_mb();
               sgi = 0;
       } else  /* out-of-band IPI (SGI1-3). */
//               sgi = ipinr - NR_IPI + 1;
               sgi = 1 << ipinr;
	flags = hard_local_irq_save();
       loongson3_send_ipi_mask(target, sgi);
       hard_local_irq_restore(flags);
}

void ipipe_send_ipi(unsigned int ipi, cpumask_t cpumask)
{
       unsigned int ipinr = ipi - IPIPE_IPI_BASE;

       smp_cross_call(&cpumask, ipinr);
}
EXPORT_SYMBOL_GPL(ipipe_send_ipi);

 /* hw IRQs off */
asmlinkage void __ipipe_grab_ipi(unsigned int sgi, struct pt_regs *regs)
{
       unsigned int ipinr, irq;
       unsigned long *pmsg;

       if (sgi) {              /* SGI1-3, OOB messages. */
               irq = sgi + NR_IPI - 1 + IPIPE_IPI_BASE;
               __ipipe_dispatch_irq(irq, IPIPE_IRQF_NOACK);
       } else {
               /* In-band IPI (0..NR_IPI-1) multiplexed over SGI0. */
               pmsg = raw_cpu_ptr(&ipi_messages);
               while (*pmsg) {
                       ipinr = ffs(*pmsg) - 1;
                       clear_bit(ipinr, pmsg);
                       irq = IPIPE_IPI_BASE + ipinr;
                       __ipipe_dispatch_irq(irq, IPIPE_IRQF_NOACK);
               }
       }

       __ipipe_exit_irq(regs);
}

#else

#define noipipe_irq_enter()    irq_enter()
#define noipipe_irq_exit()     irq_exit()

static void smp_cross_call(const struct cpumask *target, unsigned int ipinr)
{
       trace_ipi_raise(target, ipi_types[ipinr]);
       __smp_cross_call(target, ipinr);
}

#endif /* CONFIG_IPIPE */

void loongson3_ipi_interrupt(int irq)
{
	unsigned int action;
	unsigned int cpu = smp_processor_id();
#ifdef CONFIG_IPIPE
	struct pt_regs *regs;
        regs = raw_cpu_ptr(&ipipe_percpu.tick_regs);
#endif
	action = ipi_read_clear(cpu_logical_map(cpu));

	smp_mb();

	if (action & SMP_RESCHEDULE) {
		__inc_irq_stat(cpu, ipi_irqs[IPI_RESCHEDULE]);
		scheduler_ipi();
	}

	if (action & SMP_CALL_FUNCTION) {
		__inc_irq_stat(cpu, ipi_irqs[IPI_CALL_FUNC]);
		irq_enter();
		generic_smp_call_function_interrupt();
		irq_exit();
	}
#ifdef CONFIG_IPIPE
        if(action == 1<<NR_IPI){
                ipipe_handle_multi_ipi(action>>NR_IPI,regs);
        }
#endif
}

/*
 * SMP init and finish on secondary CPUs
 */
static void loongson3_init_secondary(void)
{
	unsigned int cpu = smp_processor_id();
	unsigned int imask = ECFGF_TIMER | ECFGF_IPI | ECFGF_IP2 | ECFGF_IP1 | ECFGF_IP0 | ECFGF_PC;

	/* Set interrupt mask, but don't enable */
	change_csr_ecfg(ECFG0_IM, imask);

	iocsr_writel(0xffffffff, LOONGARCH_IOCSR_IPI_EN);
	per_cpu(cpu_state, cpu) = CPU_ONLINE;
	cpu_set_core(&cpu_data[cpu],
			cpu_logical_map(cpu) % loongson_sysconf.cores_per_package);
	cpu_set_cluster(&cpu_data[cpu],
			cpu_logical_map(cpu) / loongson_sysconf.cores_per_package);
	cpu_data[cpu].package =
			cpu_logical_map(cpu) / loongson_sysconf.cores_per_package;

	if (cpu_has_extioi)
		extioi_init();
}

static void loongson3_smp_finish(void)
{

	hard_local_irq_enable();

	iocsr_writeq(0, LOONGARCH_IOCSR_MBUF0);
	pr_info("CPU#%d finished\n", smp_processor_id());
}

static void __init loongson3_smp_setup(void)
{
	int i = 0, num = 0; /* i: physical id, num: logical id */

	if (acpi_disabled) {
		init_cpu_possible(cpu_none_mask);

		while (i < MAX_CPUS) {
			if (loongson_sysconf.reserved_cpus_mask & (0x1UL << i)) {
				/* Reserved physical CPU cores */
				__cpu_number_map[i] = -1;
			} else {
				__cpu_number_map[i] = num;
				__cpu_logical_map[num] = i;
				set_cpu_possible(num, true);
				num++;
			}
			i++;
		}
		pr_info("Detected %i available CPU(s)\n", num);

		while (num < MAX_CPUS) {
			__cpu_logical_map[num] = -1;
			num++;
		}
	}

	ipi_method_init();

	iocsr_writel(0xffffffff, LOONGARCH_IOCSR_IPI_EN);

	cpu_set_core(&cpu_data[0],
		     cpu_logical_map(0) % loongson_sysconf.cores_per_package);
	cpu_set_cluster(&cpu_data[0],
		     cpu_logical_map(0) / loongson_sysconf.cores_per_package);
	cpu_data[0].package = cpu_logical_map(0) / loongson_sysconf.cores_per_package;
}

static void __init loongson3_prepare_cpus(unsigned int max_cpus)
{
	int i = 0;

	for (i = 0; i < loongson_sysconf.nr_cpus; i++) {
		set_cpu_present(i, true);

		csr_mail_send(0, __cpu_logical_map[i], 0);
	}

	per_cpu(cpu_state, smp_processor_id()) = CPU_ONLINE;
}

/*
 * Setup the PC, SP, and TP of a secondary processor and start it runing!
 */
static int loongson3_boot_secondary(int cpu, struct task_struct *idle)
{
	unsigned long entry;

	pr_info("Booting CPU#%d...\n", cpu);

	/* write PC entry in hw mailbox for secondary CPU */
	entry = (unsigned long)&smp_bootstrap;

	if (loongson_sysconf.bpi_version >= BPI_VERSION_V3)
		entry = __pa_symbol(entry);

	csr_mail_send(entry, cpu_logical_map(cpu), 0);

	/* send ipi to secondary processor */
	loongson3_send_ipi_single(cpu, SMP_BOOT_CPU);
	return 0;
}

#ifdef CONFIG_HOTPLUG_CPU
static bool is_unplug_cpu(int cpu)
{
	int i, node, logical_cpu;

	if (cpu == 0)
		return true;

	for (i = 1; i < nr_pch_pics; i++) {
		node = eiointc_get_node(i);
		logical_cpu = cpu_number_map(node * CORES_PER_EXTIOI_NODE);
		if (cpu == logical_cpu)
			return true;
	}

	return false;
}

static int loongson3_cpu_disable(void)
{
	unsigned long flags;
	unsigned int cpu = smp_processor_id();

	if (is_unplug_cpu(cpu)) {
		pr_warn("CPU %u is master cpu of node group. Cannot disable CPU\n", cpu);
		return -EBUSY;
	}

	numa_remove_cpu(cpu);
	set_cpu_online(cpu, false);
	calculate_cpu_foreign_map();
	flags = hard_local_irq_save();
	fixup_irqs();
	hard_local_irq_restore(flags);
	local_flush_tlb_all();

	return 0;
}


static void loongson3_cpu_die(unsigned int cpu)
{
	while (per_cpu(cpu_state, cpu) != CPU_DEAD)
		cpu_relax();

	mb();
}

/* To shutdown a core in Loongson 3, the target core should go to XKPRANGE
 * and flush all L1 entries at first. Then, another core (usually Core 0)
 * can safely disable the clock of the target core. loongson3_play_dead()
 * is called via XKPRANGE (uncached and unmmaped) */

static void loongson3_play_dead(int *state_addr)
{
	register int val;
	register void *addr;
	unsigned int action;
	void (*boot_cpu)(void);

	if (cpu_has_hypervisor)
		/* Tell __cpu_die() that this CPU is now safe to dispose of */
		__this_cpu_write(cpu_state, CPU_DEAD);

	else {
		__asm__ __volatile__(
			"   li.d %[addr], 0x8000000000000000\n"
			"1: cacop 0x8, %[addr], 0           \n" /* flush L1 ICache */
			"   cacop 0x8, %[addr], 1           \n"
			"   cacop 0x8, %[addr], 2           \n"
			"   cacop 0x8, %[addr], 3           \n"
			"   cacop 0x9, %[addr], 0           \n" /* flush L1 DCache */
			"   cacop 0x9, %[addr], 1           \n"
			"   cacop 0x9, %[addr], 2           \n"
			"   cacop 0x9, %[addr], 3           \n"
			"   addi.w %[sets], %[sets], -1   \n"
			"   addi.d %[addr], %[addr], 0x40 \n"
			"   bnez  %[sets], 1b             \n"
			"   li.d %[addr], 0x8000000000000000\n"
			"2: cacop 0xa, %[addr], 0           \n" /* flush L1 VCache */
			"   cacop 0xa, %[addr], 1           \n"
			"   cacop 0xa, %[addr], 2           \n"
			"   cacop 0xa, %[addr], 3           \n"
			"   cacop 0xa, %[addr], 4           \n"
			"   cacop 0xa, %[addr], 5           \n"
			"   cacop 0xa, %[addr], 6           \n"
			"   cacop 0xa, %[addr], 7           \n"
			"   cacop 0xa, %[addr], 8           \n"
			"   cacop 0xa, %[addr], 9           \n"
			"   cacop 0xa, %[addr], 10          \n"
			"   cacop 0xa, %[addr], 11          \n"
			"   cacop 0xa, %[addr], 12          \n"
			"   cacop 0xa, %[addr], 13          \n"
			"   cacop 0xa, %[addr], 14          \n"
			"   cacop 0xa, %[addr], 15          \n"
			"   addi.w %[vsets], %[vsets], -1   \n"
			"   addi.d %[addr], %[addr], 0x40   \n"
			"   bnez  %[vsets], 2b              \n"
			"   li.w    %[val], 0x7               \n" /* *state_addr = CPU_DEAD; */
			"   st.w  %[val], %[state_addr], 0  \n"
			"   dbar 0                          \n"
			"   cacop 0x11, %[state_addr], 0    \n" /* flush entry of *state_addr */
			: [addr] "=&r" (addr), [val] "=&r" (val)
			: [state_addr] "r" (state_addr),
			  [sets] "r" (cpu_data[smp_processor_id()].dcache.sets),
			  [vsets] "r" (cpu_data[smp_processor_id()].vcache.sets));
	}

	/* enable ipi interrupt*/
	hard_local_irq_enable();
	set_csr_ecfg(ECFGF_IPI);

	do {
		asm volatile("idle 0\n\t");
		boot_cpu = (void *)((u64)iocsr_readl(LOONGARCH_IOCSR_MBUF0));
	} while (boot_cpu == 0);
	boot_cpu = (void *)iocsr_readq(LOONGARCH_IOCSR_MBUF0);

	/* clear ipi interrupt */
	action = iocsr_readl(LOONGARCH_IOCSR_IPI_STATUS);
	iocsr_writel(action, LOONGARCH_IOCSR_IPI_CLEAR);

	boot_cpu();
	unreachable();
}

void play_dead(void)
{
	int *state_addr;
	unsigned int cpu = smp_processor_id();
	void (*play_dead_uncached)(int *);

	idle_task_exit();

	play_dead_uncached = (void *)TO_UNCAC(__pa((unsigned long)loongson3_play_dead));
	state_addr = &per_cpu(cpu_state, cpu);
	mb();
	play_dead_uncached(state_addr);
}

static int loongson3_disable_clock(unsigned int cpu)
{
	uint64_t core_id = cpu_core(&cpu_data[cpu]);
	uint64_t package_id = cpu_data[cpu].package;

	LOONGSON_FREQCTRL(package_id) &= ~(1 << (core_id * 4 + 3));

	return 0;
}

static int loongson3_enable_clock(unsigned int cpu)
{
	uint64_t core_id = cpu_core(&cpu_data[cpu]);
	uint64_t package_id = cpu_data[cpu].package;

	LOONGSON_FREQCTRL(package_id) |= 1 << (core_id * 4 + 3);

	return 0;
}

static int register_loongson3_notifier(void)
{
	if (!cpu_has_scalefreq)
		return 0;

	return cpuhp_setup_state_nocalls(CPUHP_LOONGARCH_SOC_PREPARE,
					 "loongarch/loongson:prepare",
					 loongson3_enable_clock,
					 loongson3_disable_clock);
}
early_initcall(register_loongson3_notifier);

#endif

const struct plat_smp_ops loongson3_smp_ops = {
	.send_ipi_single = loongson3_send_ipi_single,
	.send_ipi_mask = loongson3_send_ipi_mask,
	.smp_setup = loongson3_smp_setup,
	.prepare_cpus = loongson3_prepare_cpus,
	.boot_secondary = loongson3_boot_secondary,
	.init_secondary = loongson3_init_secondary,
	.smp_finish = loongson3_smp_finish,
#ifdef CONFIG_HOTPLUG_CPU
	.cpu_disable = loongson3_cpu_disable,
	.cpu_die = loongson3_cpu_die,
#endif
};

/*
 * Power management
 */
#ifdef CONFIG_PM

static int loongson3_ipi_suspend(void)
{
        return 0;
}

static void loongson3_ipi_resume(void)
{
	iocsr_writel(0xffffffff, LOONGARCH_IOCSR_IPI_EN);
}

static struct syscore_ops loongson3_ipi_syscore_ops = {
	.resume         = loongson3_ipi_resume,
	.suspend        = loongson3_ipi_suspend,
};

/*
 * Enable boot cpu ipi before enabling nonboot cpus
 * during syscore_resume.
 * */
static int __init ipi_pm_init(void)
{
	register_syscore_ops(&loongson3_ipi_syscore_ops);
        return 0;
}

core_initcall(ipi_pm_init);
#endif
