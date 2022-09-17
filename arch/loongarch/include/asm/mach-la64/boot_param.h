/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_MACH_LOONGSON64_BOOT_PARAM_H_
#define __ASM_MACH_LOONGSON64_BOOT_PARAM_H_
#ifdef CONFIG_VT
#include <linux/screen_info.h>
#endif

#define ADDRESS_TYPE_SYSRAM	1
#define ADDRESS_TYPE_RESERVED	2
#define ADDRESS_TYPE_ACPI	3
#define ADDRESS_TYPE_NVS	4
#define ADDRESS_TYPE_PMEM	5

#define LOONGSON3_BOOT_MEM_MAP_MAX	128
#define RT_MAP_START			100
#define FIX_MAP_ENTRY			32

/* mask of the flags in bootparamsinterface */
#define BPI_FLAGS_UEFI_SUPPORTED	BIT(0)
#define BPI_FLAGS_SOC_CPU		BIT(1)

struct loongson_board_info {
	int bios_size;
	char *bios_vendor;
	char *bios_version;
	char *bios_release_date;
	char *board_name;
	char *board_vendor;
};

struct loongson_system_configuration {
	char *cpuname;
	int nr_cpus;
	int nr_nodes;
	int cores_per_node;
	int cores_per_package;
	u16 boot_cpu_id;
	u64 reserved_cpus_mask;
	u64 ht_control_base;
	u64 restart_addr;
	u64 poweroff_addr;
	u64 suspend_addr;
	u64 vgabios_addr;
	u32 dma_mask_bits;
	u32 msi_address_lo;
	u32 msi_address_hi;
	u32 msi_base_irq;
	u32 msi_last_irq;
	u32 io_base_irq;
	u32 io_last_irq;
	u32 bpi_version;
	u8 pcie_wake_enabled;
	u8 is_soc_cpu;
};

#define LOONGSON_DMA_MASK_BIT			64
#define LOONGSON_MEM_SIGNATURE			"MEM"
#define LOONGSON_VBIOS_SIGNATURE		"VBIOS"
#define LOONGSON_EFIBOOT_SIGNATURE		"BPI"
#define LOONGSON_SCREENINFO_SIGNATURE	"SINFO"
#define LOONGSON_EFIBOOT_VERSION		1000

/* Values for Version BPI */

enum bpi_version {
	BPI_VERSION_NONE = 0,
	BPI_VERSION_V1 = 1000,
	BPI_VERSION_V2 = 1001,
	BPI_VERSION_V3 = 1002,
};

union extlist_line {
	struct	_extention_list_hdr	*extlist;
	u64		ext_offset;
};

struct boot_params {
	u64		signature;	/* {"BPIXXXXX"} */
	void	*systemtable;
	union extlist_line ext_location;
	u64		flags;
} __attribute__((packed));

struct _extention_list_hdr {
	u64	signature;
	u32	length;
	u8	revision;
	u8	checksum;
	union extlist_line next_ext;
} __attribute__((packed));

struct loongsonlist_mem_map {
	struct	_extention_list_hdr header;	/*{"M", "E", "M"}*/
	u8	map_count;
	struct	_loongson_mem_map {
		u32 mem_type;
		u64 mem_start;
		u64 mem_size;
	} __attribute__((packed))map[LOONGSON3_BOOT_MEM_MAP_MAX];
} __attribute__((packed));

struct priv_mmap {
	struct	_extention_list_hdr header;	/*{"M", "E", "M"}*/
	u8	map_count;
	u32	desc_ver;
	struct efi_mmap {
		u32 mem_type;
		u32 pad;
		u64 mem_start;
		u64 virt_addr;
		u64 mem_size;
		u64 attribute;
	} __attribute__((packed))map[LOONGSON3_BOOT_MEM_MAP_MAX];
} __attribute__((packed));

struct loongsonlist_vbios {
	struct	_extention_list_hdr header;	/* {VBIOS} */
	u64	vbios_addr;
} __attribute__((packed));

struct loongsonlist_screeninfo{
	struct  _extention_list_hdr header;
	struct  screen_info si;
};

extern void *loongson_fdt_blob;
extern struct loongson_board_info b_info;
extern struct boot_params *efi_bp;
extern void *g_mmap;
extern struct loongson_system_configuration loongson_sysconf;
extern char __dtb_start[];
unsigned int walk_mem_entry(struct  _loongson_mem_map *map);
#endif
