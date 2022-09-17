// SPDX-License-Identifier: GPL-2.0
/*
 * EFI partition
 *
 * Just for ACPI here, complete it when implementing EFI runtime.
 *
 * Copyright (C) 2020 Loongson Technology Co., Ltd.
 *
 * lvjianmin: <lvjianmin@loongson.cn>
 * Huacai Chen: <chenhuacai@loongson.cn>
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/efi.h>
#include <linux/acpi.h>
#include <linux/efi-bgrt.h>
#include <linux/export.h>
#include <linux/bootmem.h>
#include <linux/slab.h>
#include <linux/memblock.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/time.h>
#include <linux/io.h>
#include <linux/reboot.h>
#include <linux/bcd.h>
#include <asm/tlb.h>
#include <asm/efi.h>
#include <boot_param.h>
#include <loongson.h>

unsigned long loongarch_efi_facility;
extern unsigned long loongson_efi_facility;

efi_config_table_type_t arch_tables[] __initdata = {
	{NULL_GUID, NULL, NULL},
};

static void create_tlb(u32 index, u64 vppn, u32 ps, u32 mat)
{
	unsigned long tlblo0, tlblo1;

	write_csr_pagesize(ps);

	tlblo0 = vppn | CSR_TLBLO0_V | CSR_TLBLO0_WE |
		CSR_TLBLO0_GLOBAL | (mat << CSR_TLBLO0_CCA_SHIFT);
	tlblo1 = tlblo0 + (1 << ps);

	csr_xchgl(index, CSR_TLBIDX_IDX, LOONGARCH_CSR_TLBIDX);
	csr_xchgl(0, CSR_TLBIDX_EHINV, LOONGARCH_CSR_TLBIDX);
	csr_writeq(vppn, LOONGARCH_CSR_TLBEHI);
	csr_writeq(tlblo0, LOONGARCH_CSR_TLBELO0);
	csr_writeq(tlblo1, LOONGARCH_CSR_TLBELO1);

	tlb_write_indexed();
}

static void destroy_entry(void)
{
	write_csr_pagesize(PS_DEFAULT_SIZE);
	local_flush_tlb_all();
}

static void fix_efi_entry(u32 n, efi_memory_desc_t *virtual_map)
{
	unsigned int i, sz;
	unsigned long vppn0, vppn1;
	unsigned int index = MTLB_ENTRY_FIX_INDEX;
	efi_memory_desc_t *rt = virtual_map;

	for (i = 0; i < n; i++, rt++) {
		sz = roundup_pow_of_two(rt->num_pages << EFI_PAGE_SHIFT);

		vppn0 = rt->phys_addr & (~(sz - 1));
		create_tlb(index++, vppn0, fls(sz) - 2, 1);

		vppn1 = vppn0 + sz;
		create_tlb(index++, vppn1, fls(sz) - 2, 1);
	}
	/*
	 * There is relevant debugging information in SetVirtualAddressMap(),
	 * and a temporary fix TLB of the serial port register address needs to
	 * be added.
	 */
	create_tlb(index++, LOONGSON_REG_BASE, PS_4K, 0);
}

static efi_status_t __init set_virtual_map(
	efi_set_virtual_address_map_t *svam,
	u64 map_size, u64 desc_size,
	u32	desc_version, efi_memory_desc_t *virtual_map)
{
	efi_status_t status;

	fix_efi_entry(map_size / desc_size, virtual_map);

	status = svam(map_size, desc_size, desc_version,
			(efi_memory_desc_t *)TO_PHYS((unsigned long)virtual_map));

	destroy_entry();
	return status;
}

/*
 * enter_virt_mode() - create a virtual mapping for the EFI memory map and call
 * efi_set_virtual_address_map enter virtual for runtime service
 *
 * This function populates the virt_addr fields of all memory region descriptors
 * in @memory_map whose EFI_MEMORY_RUNTIME attribute is set. Those descriptors
 * are also copied to @runtime_map, and their total count is returned in @count.
 */
static unsigned int __init enter_virt_mode(void)
{
	efi_status_t status;
	int i;
	unsigned int count = 0;
	unsigned long attr;
	efi_runtime_services_t *rt;
	efi_set_virtual_address_map_t *svam;
	efi_memory_desc_t *runtime_map, *out;
	struct priv_mmap *map;

	unsigned int desc_size = sizeof(struct efi_mmap);

	if (loongson_sysconf.bpi_version < BPI_VERSION_V3)
		return EFI_SUCCESS;

	map = (struct priv_mmap *)g_mmap;
	out = runtime_map = (efi_memory_desc_t *)&map->map[RT_MAP_START];

	for (i = 0; i < map->map_count; i++) {
		attr = map->map[i].attribute;
		if (!(attr & EFI_MEMORY_RUNTIME))
			continue;

		map->map[i].virt_addr = map->map[i].mem_start + CAC_BASE;
		map->map[i].mem_size = map->map[i].mem_size >> EFI_PAGE_SHIFT;

		memcpy(out, &map->map[i], desc_size);
		out = (void *)out + desc_size;
		++count;

	}

	rt = early_memremap_ro((unsigned long)efi.systab->runtime, sizeof(*rt));

	/* Install the new virtual address map */
	svam = rt->set_virtual_address_map;

	status = set_virtual_map(svam, desc_size * count,
			desc_size, map->desc_ver, runtime_map);
	/*
	 * If the call to SetVirtualAddressMap() failed, we need to
	 * signal that to the incoming kernel but proceed normally otherwise.
	 */
	if (status != EFI_SUCCESS)
		return -1;

	return 0;
}

void __init efi_runtime_init(void)
{
	efi_status_t status;

	if (!efi_enabled(EFI_BOOT) || !efi.systab->runtime)
		goto skip;

	status = enter_virt_mode();

	if (!efi_runtime_disabled() && !status) {
		efi.runtime	= (unsigned long)efi.systab->runtime;
		efi.runtime_version = efi.systab->hdr.revision;

		efi_native_runtime_setup();
		set_bit(EFI_RUNTIME_SERVICES, &efi.flags);
		return;
	}
skip:
	pr_warning("UEFI runtime services will not be available!\n");
}

void __init efi_init(void)
{
	if (!efi_bp)
		return;

	efi.systab = (efi_system_table_t *)early_memremap_ro
		((unsigned long)efi_bp->systemtable, sizeof(efi.systab));

	if (!efi.systab) {
		pr_err("Can't find EFI system table.\n");
		return;
	}
	set_bit(EFI_64BIT, &efi.flags);
	efi.config_table = (unsigned long)efi.systab->tables;

	efi_config_init(arch_tables);
}
