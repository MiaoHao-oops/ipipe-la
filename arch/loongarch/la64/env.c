// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 Loongson Technology Co., Ltd.
 * Author: Huacai Chen <chenhuacai@loongson.cn>
 *
 * This program is free software; you can redistribute	it and/or modify it
 * under  the terms of	the GNU General	 Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */
#include <linux/export.h>
#include <linux/acpi.h>
#include <linux/efi.h>
#include <asm/fw.h>
#include <asm/time.h>
#include <asm/bootinfo.h>
#include <asm/dma.h>
#include <loongson.h>
#include <loongson-pch.h>

void *g_mmap;
struct boot_params *efi_bp;
struct loongsonlist_vbios *pvbios;
struct loongson_system_configuration loongson_sysconf;

u64 loongson_chipcfg[MAX_PACKAGES];
u64 loongson_chiptemp[MAX_PACKAGES];
u64 loongson_freqctrl[MAX_PACKAGES];
unsigned long long smp_group[MAX_PACKAGES];

void *loongson_fdt_blob;
EXPORT_SYMBOL(loongson_sysconf);

static void __init loongson_regaddr_set(u64 *loongson_reg, const u64 addr, int num)
{
	u64 i;

	for (i = 0; i < num; i++) {
		*loongson_reg = (i << 44) | addr;
		loongson_reg++;
	}
}

static u8 ext_listhdr_checksum(u8 *buffer, u32 length)
{
	u8 sum = 0;
	u8 *end = buffer + length;

	while (buffer < end) {
		sum = (u8)(sum + *(buffer++));
	}

	return (sum);
}

extern struct loongsonlist_mem_map global_mem_map;

static int parse_mem(struct _extention_list_hdr *head)
{
	struct loongsonlist_mem_map_legacy *ptr;
	int i;

	g_mmap = head;
	if (ext_listhdr_checksum((u8 *)g_mmap, head->length)) {
		printk("mem checksum error\n");
		return -EPERM;
	}

	if (loongson_sysconf.bpi_version < BPI_VERSION_V3) {
		ptr = (struct loongsonlist_mem_map_legacy *)head;

		pr_info("convert legacy mem map to new mem map.\n");
		memcpy(&global_mem_map, ptr, sizeof(global_mem_map.header));
		global_mem_map.map_count = ptr->map_count;
		for (i = 0; i < ptr->map_count; i++) {
			global_mem_map.map[i].mem_type = ptr->map[i].mem_type;
			global_mem_map.map[i].mem_start = ptr->map[i].mem_start;
			global_mem_map.map[i].mem_size = ptr->map[i].mem_size;
			pr_info("mem_type:%d ", ptr->map[i].mem_type);
			pr_info("mem_start:0x%llx, mem_size:0x%llx Bytes\n",
				ptr->map[i].mem_start, ptr->map[i].mem_size);
		}
		g_mmap = &global_mem_map;
	}
	return 0;
}

static int parse_vbios(struct _extention_list_hdr *head)
{
	pvbios = (struct loongsonlist_vbios *)head;

	if (ext_listhdr_checksum((u8 *)pvbios, head->length)) {
		printk("vbios_addr checksum error\n");
		return -EPERM;
	}
	loongson_sysconf.vgabios_addr =
		(unsigned long)early_memremap_ro(pvbios->vbios_addr,
				sizeof(unsigned long));

	return 0;
}

static int parse_screeninfo(struct _extention_list_hdr *head)
{
	struct loongsonlist_screeninfo *pscreeninfo;

	pscreeninfo = (struct loongsonlist_screeninfo *)head;
	if (ext_listhdr_checksum((u8 *)pscreeninfo, head->length)) {
		printk("screeninfo_addr checksum error\n");
		return -EPERM;
	}

	memcpy(&screen_info, &pscreeninfo->si, sizeof(screen_info));
	return 0;
}

static int list_find(struct boot_params *bp)
{
	struct _extention_list_hdr *fhead = NULL;
	unsigned long index;

	if (loongson_sysconf.bpi_version >= BPI_VERSION_V3)
		fhead = (struct _extention_list_hdr *)((char *)bp
				+ bp->ext_location.ext_offset);
	else
		fhead = (struct _extention_list_hdr*)early_memremap_ro
			((unsigned long)bp->ext_location.extlist, sizeof(fhead));

	if (!fhead) {
		printk("the bp ext struct empty!\n");
		return -1;
	}

	do {
		if (memcmp(&(fhead->signature), LOONGSON_MEM_SIGNATURE, 3) == 0) {
			if (parse_mem(fhead) !=0) {
				printk("parse mem failed\n");
				return -EPERM;
			}
		} else if (memcmp(&(fhead->signature), LOONGSON_VBIOS_SIGNATURE, 5) == 0) {
			if (parse_vbios(fhead) != 0) {
				printk("parse vbios failed\n");
				return -EPERM;
			}
		} else if (memcmp(&(fhead->signature), LOONGSON_SCREENINFO_SIGNATURE, 5) == 0) {
			if (parse_screeninfo(fhead) != 0) {
				printk("parse screeninfo failed\n");
				return -EPERM;
			}
		}
		if (loongson_sysconf.bpi_version >= BPI_VERSION_V3) {
			index = fhead->next_ext.ext_offset;
			fhead = (struct _extention_list_hdr *)((char *)bp
					+ fhead->next_ext.ext_offset);
		} else {
// #ifdef CONFIG_RUN_ON_QEMU
			index = (unsigned long)fhead->next_ext.extlist;
			fhead = (struct _extention_list_hdr *)early_memremap_ro
				((unsigned long)fhead->next_ext.extlist, sizeof(fhead));
// #else
			// fhead = (struct _extention_list_hdr *)fhead->next_ext.extlist;
			// index = (unsigned long)fhead;
// #endif
		}

	} while (index);

	return 0;
}

static int get_bpi_version(u64 *signature)
{
	u8 data[9];
	int version = BPI_VERSION_NONE;
	data[8] = 0;
	memcpy(data, signature, sizeof(*signature));
	if (kstrtoint(&data[3], 10, &version))
		return BPI_VERSION_NONE;
	return version;
}

static void __init parse_bpi_flags(void)
{
#ifdef CONFIG_EFI
	if (efi_bp->flags & BPI_FLAGS_UEFI_SUPPORTED)
		set_bit(EFI_BOOT, &efi.flags);
	else
		clear_bit(EFI_BOOT, &efi.flags);
#endif
	if (efi_bp->flags & BPI_FLAGS_SOC_CPU)
		loongson_sysconf.is_soc_cpu = 1;
}

void __init fw_init_env(void)
{
	efi_bp = (struct boot_params *)early_memremap_ro((unsigned long)_fw_envp,
			SZ_64K);
	loongson_sysconf.bpi_version = get_bpi_version(&efi_bp->signature);
	pr_info("BPI%d with boot flags %llx.\n", loongson_sysconf.bpi_version, efi_bp->flags);
	if (loongson_sysconf.bpi_version == BPI_VERSION_NONE)
			printk("Fatal error, incorrect BPI version: %d\n",
					loongson_sysconf.bpi_version);

	else if (loongson_sysconf.bpi_version >= BPI_VERSION_V2)
		parse_bpi_flags();

	loongson_regaddr_set(smp_group, 0x800000001fe01000, 16);

	loongson_sysconf.ht_control_base = 0x80000EFDFB000000;

	loongson_regaddr_set(loongson_chipcfg, 0x800000001fe00180, 16);

	loongson_regaddr_set(loongson_chiptemp, 0x800000001fe0019c, 16);
	loongson_regaddr_set(loongson_freqctrl, 0x800000001fe001d0, 16);

	loongson_sysconf.io_base_irq = LOONGSON_PCH_IRQ_BASE;
	loongson_sysconf.io_last_irq = LOONGSON_PCH_IRQ_BASE + 256;
	loongson_sysconf.msi_base_irq = LOONGSON_PCI_MSI_IRQ_BASE;
	loongson_sysconf.msi_last_irq = LOONGSON_PCI_MSI_IRQ_BASE + 192;
	loongson_sysconf.msi_address_hi = 0;
	loongson_sysconf.msi_address_lo = 0x2FF00000;
	loongson_sysconf.dma_mask_bits = LOONGSON_DMA_MASK_BIT;

	if (list_find(efi_bp))
		printk("Scan bootparm failed\n");
}

static int __init init_cpu_fullname(void)
{
 	int cpu;

	if (loongson_sysconf.cpuname && !strncmp(loongson_sysconf.cpuname, "Loongson", 8)) {
		for (cpu = 0; cpu < NR_CPUS; cpu++) {
			__cpu_full_name[cpu] = loongson_sysconf.cpuname;
		}
	}
 	return 0;
}
arch_initcall(init_cpu_fullname);
