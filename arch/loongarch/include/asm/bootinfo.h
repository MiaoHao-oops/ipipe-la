/* SPDX-License-Identifier: GPL-2.0 */
/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file COPYING in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 1995, 1996, 2003 by Ralf Baechle
 * Copyright (C) 1995, 1996 Andreas Busse
 * Copyright (C) 1995, 1996 Stoned Elipot
 * Copyright (C) 1995, 1996 Paul M. Antoine.
 * Copyright (C) 2009       Zhang Le
 * Copyright (C) 2020 Loongson Technology Co., Ltd.
 */
#ifndef _ASM_BOOTINFO_H
#define _ASM_BOOTINFO_H

#include <linux/types.h>
#include <asm/setup.h>

const char *get_system_type(void);

#define BOOT_MEM_MAP_MAX	64
#define BOOT_MEM_RAM		1
#define BOOT_MEM_ROM_DATA	2
#define BOOT_MEM_RESERVED	3
#define BOOT_MEM_INIT_RAM	4

/*
 * A memory map that's built upon what was determined
 * or specified on the command line.
 */
struct boot_mem_map {
	int nr_map;
	struct boot_mem_map_entry {
		phys_addr_t addr;	/* start of memory segment */
		phys_addr_t size;	/* size of memory segment */
		long type;		/* type of memory segment */
	} map[BOOT_MEM_MAP_MAX];
};

extern struct boot_mem_map boot_mem_map;

extern void add_memory_region(phys_addr_t start, phys_addr_t size, long type);
extern void detect_memory_region(phys_addr_t start, phys_addr_t sz_min,  phys_addr_t sz_max);

extern void platform_init(void);
extern void plat_swiotlb_setup(void);
extern void prom_free_prom_memory(void);

extern void free_init_pages(const char *what, unsigned long begin, unsigned long end);

extern void (*free_init_pages_eva)(void *begin, void *end);

/*
 * Initial kernel command line, usually setup by platform_init()
 */
extern char arcs_cmdline[COMMAND_LINE_SIZE];

/*
 * Registers a0, a1, a3 and a4 as passed to the kernel entry by firmware
 */
extern unsigned long fw_arg0, fw_arg1, fw_arg2, fw_arg3;

#ifdef CONFIG_USE_OF
extern unsigned long fw_passed_dtb;
#endif

/*
 * Platform memory detection hook called by setup_arch
 */
extern void plat_mem_setup(void);

#ifdef CONFIG_USE_OF
/**
 * plat_get_fdt() - Return a pointer to the platform's device tree blob
 *
 * This function provides a platform independent API to get a pointer to the
 * flattened device tree blob. The interface between bootloader and kernel
 * is not consistent across platforms so it is necessary to provide this
 * API such that common startup code can locate the FDT.
 *
 * This is used by the KASLR code to get command line arguments and random
 * seed from the device tree. Any platform wishing to use KASLR should
 * provide this API and select SYS_SUPPORTS_RELOCATABLE.
 *
 * Return: Pointer to the flattened device tree blob.
 */
extern void *plat_get_fdt(void);

#ifdef CONFIG_RELOCATABLE

/**
 * plat_fdt_relocated() - Update platform's information about relocated dtb
 *
 * This function provides a platform-independent API to set platform's
 * information about relocated DTB if it needs to be moved due to kernel
 * relocation occurring at boot.
 */
void plat_fdt_relocated(void *new_location);

#endif /* CONFIG_RELOCATABLE */
#endif /* CONFIG_USE_OF */

#endif /* _ASM_BOOTINFO_H */
