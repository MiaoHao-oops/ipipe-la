/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2009 Lemote, Inc.
 * Author: Wu Zhangjin <wuzhangjin@gmail.com>
 * Copyright (C) 2020 Loongson Technology Corporation Limited
 *
 * This program is free software; you can redistribute	it and/or modify it
 * under  the terms of	the GNU General	 Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */

#ifndef __ASM_MACH_LOONGSON64_LOONGSON_H
#define __ASM_MACH_LOONGSON64_LOONGSON_H

#include <linux/io.h>
#include <linux/init.h>
#include <linux/irq.h>
#include <linux/pci.h>
#include <asm/addrspace.h>
#include <boot_param.h>

/* machine-specific reboot/halt operation */
extern void mach_prepare_reboot(void);
extern void mach_prepare_shutdown(void);

extern const struct plat_smp_ops loongson3_smp_ops;

/* loongson-specific command line, env and memory initialization */

/* irq operation functions */
extern void __init mach_init_irq(void);
extern void mach_irq_dispatch(unsigned int pending);

extern void __init fw_init_env(void);
extern void __init fw_init_environ(void);
extern void __init fw_init_memory(void);
extern void __init fw_init_numa_memory(void);

#define LOONGSON_REG(x) \
	(*(volatile u32 *)((char *)TO_UNCAC(LOONGSON_REG_BASE) + (x)))

#define LOONGSON_IRQ_BASE	32
#define LOONGSON2_PERFCNT_IRQ	(LOONGARCH_CPU_IRQ_BASE + 6) /* cpu perf counter */

#include <linux/interrupt.h>
static inline void do_perfcnt_IRQ(void)
{
#if IS_ENABLED(CONFIG_OPROFILE)
	do_IRQ(LOONGSON2_PERFCNT_IRQ);
#endif
}

#define LOONGSON_LIO_BASE	0x18000000
#define LOONGSON_LIO_SIZE	0x00100000	/* 1M */
#define LOONGSON_LIO_TOP	(LOONGSON_LIO_BASE+LOONGSON_LIO_SIZE-1)

#define LOONGSON_BOOT_BASE	0x1c000000
#define LOONGSON_BOOT_SIZE	0x02000000	/* 32M */
#define LOONGSON_BOOT_TOP	(LOONGSON_BOOT_BASE+LOONGSON_BOOT_SIZE-1)

#define LOONGSON_REG_BASE	0x1fe00000
#define LOONGSON_REG_SIZE	0x00100000	/* 8K */
#define LOONGSON_REG_TOP	(LOONGSON_REG_BASE+LOONGSON_REG_SIZE-1)

/* GPIO Regs - r/w */

#define LOONGSON_GPIODATA		LOONGSON_REG(0x11c)
#define LOONGSON_GPIOIE			LOONGSON_REG(0x120)
#define LOONGSON_REG_GPIO_BASE		(LOONGSON_REG_BASE + 0x11c)

#define MAX_PACKAGES 16

/* Chip Config registor of each physical cpu package, PRid >= Loongson-2F */
extern u64 loongson_chipcfg[MAX_PACKAGES];
#define LOONGSON_CHIPCFG(id) (*(volatile u32 *)(loongson_chipcfg[id]))

/* Chip Temperature registor of each physical cpu package, PRid >= Loongson-3A */
extern u64 loongson_chiptemp[MAX_PACKAGES];
#define LOONGSON_CHIPTEMP(id) (*(volatile u32 *)(loongson_chiptemp[id]))

/* Freq Control register of each physical cpu package, PRid >= Loongson-3B */
extern u64 loongson_freqctrl[MAX_PACKAGES];
#define LOONGSON_FREQCTRL(id) (*(volatile u32 *)(loongson_freqctrl[id]))

#define LOONGSON3_NODE_BASE(x)  (0x8000000000000000 | \
		(((unsigned long)x & 0xf) << 44))

#ifdef CONFIG_CPU_SUPPORTS_CPUFREQ
#include <linux/cpufreq.h>
extern struct cpufreq_frequency_table loongson2_clockmod_table[];
extern struct cpufreq_frequency_table loongson3_clockmod_table[];
extern struct cpufreq_frequency_table *loongson3a4000_clockmod_table;
extern struct cpufreq_frequency_table ls3a4000_normal_table[];
extern struct cpufreq_frequency_table ls3a4000_boost_table[];
extern void ls3a4000_freq_table_switch(struct cpufreq_frequency_table *table);
extern int ls3a4000_set_boost(int mode, int freq_level);
extern int ls3a4000_freq_scale(struct cpufreq_policy* policy, unsigned long rate);

#define BOOST_FREQ_MAX 2000000000

#define CPU_ID_FIELD    0xf
#define NODE_FIELD      0xf0
#define FREQ_FIELD      0xf00
#define VOLTAGE_FIELD   0xf000
#define VOLTAGE_CHANGE_FIELD    0xc0000

#define BOOST_NORMAL_FIELD  0xc0000

#define COMMAND_FIELD   0x7f000000
#define COMPLETE_STATUS 0x80000000
#define VOLTAGE_COMMAND 0x21

#define DVFS_INFO	0x22
#define DVFS_INFO_BOOST_LEVEL	0x23
#define DVFS_INFO_MIN_FREQ	0xf
#define DVFS_INFO_MAX_FREQ	0xf0
#define DVFS_INFO_BOOST_CORE_FREQ	0xff00
#define DVFS_INFO_NORMAL_CORE_UPPER_LIMIT	0xf0000
#define DVFS_INFO_BOOST_CORES	0xf00000

#define BOOST_MODE	0x80000
#define NORMAL_MODE	0x40000

#endif

#ifdef CONFIG_HOTPLUG_CPU
extern int disable_unused_cpus(void);
#else
static inline int disable_unused_cpus(void) { return 0; }
#endif

/*
 * Loongson specific extension encodings
 */

#define MBIT_U(bit)		(1U << (bit))

/* cpucfg register 2*/
#define LOONGARCH_LSE_LAMO		MBIT_U(12)

#define CPU_TO_CONF(x)	(0x800000001fe00000 | (((unsigned long)x & 0x3) << 8) \
		| (((unsigned long)x & 0xc) << 42))

#define xconf_readl(addr) readl(addr)
#define xconf_readq(addr) readq(addr)

static inline void xconf_writel(u32 val, volatile void __iomem *addr)
{
	asm volatile (
	"	st.w	%[v], %[hw], 0	\n"
	"	ld.b	$r0, %[hw], 0	\n"
	:
	: [hw] "r" (addr), [v] "r" (val)
	);
}

static inline void xconf_writeq(u64 val64, volatile void __iomem *addr)
{

	asm volatile (
	"	st.d	%[v], %[hw], 0	\n"
	"	ld.b	$r0, %[hw], 0	\n"
	:
	: [hw] "r" (addr),  [v] "r" (val64)
	);
}

#endif /* __ASM_MACH_LOONGSON64_LOONGSON_H */
