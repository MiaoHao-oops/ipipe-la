// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2013,2014 Linaro Limited
 *     Roy Franz <roy.franz@linaro.org
 * Copyright (C) 2013 Red Hat, Inc.
 *     Mark Salter <msalter@redhat.com>
 * Copyright (C) 2020 Loongson, Inc.
 *     Yun Liu <liuyun@loongson.cn>
 *
 * This file is part of the Linux kernel, and is made available under the
 * terms of the GNU General Public License version 2.
 *
 */

#include <linux/efi.h>
#include <linux/sort.h>
#include <asm/efi.h>
#include <linux/mm.h>
#include <asm/addrspace.h>
#include "efistub.h"

#define CMDLINE_MAX_SIZE 0x200
#define MAX_ARG_COUNT 128

typedef void __noreturn (*jump_kernel_func)(unsigned int, char **, unsigned long long);
typedef struct _extention_list_hdr ext_struct;

static unsigned int map_entry[LOONGSON3_BOOT_MEM_MAP_MAX];
static struct efi_mmap mmap_array[EFI_MAX_MEMORY_TYPE][LOONGSON3_BOOT_MEM_MAP_MAX];
static char cmdline_mmap_array[CMDLINE_MAX_SIZE];

void efi_char16_printk(efi_system_table_t *sys_table_arg_arg,
			      efi_char16_t *str)
{
	struct efi_simple_text_output_protocol *out;

	out = (struct efi_simple_text_output_protocol *)sys_table_arg_arg->con_out;
	out->output_string(out, str);
}

unsigned char efi_crc8(char *buff, int size)
{
	int sum, cnt;

	for (sum = 0, cnt = 0; cnt < size; cnt++)
		sum = (char) (sum + *(buff + cnt));

	return (char)(0x100 - sum);
}

/**
 * get_efi_config_table() - retrieve UEFI configuration table
 * @guid:	GUID of the configuration table to be retrieved
 * Return:	pointer to the configuration table or NULL
 */
void *get_efi_config_table(efi_system_table_t *sys_table_arg,
		efi_guid_t guid)
{
	unsigned long tables = efi_table_attr(NULL, tables, sys_table_arg);
	int nr_tables = efi_table_attr(NULL, nr_tables, sys_table_arg);
	int i;

	for (i = 0; i < nr_tables; i++) {
		efi_config_table_t *t = (void *)tables;

		if (efi_guidcmp(t->guid, guid) == 0)
			return (void *)efi_table_attr(NULL, table, t);

		tables += efi_is_64bit() ? sizeof(efi_config_table_t)
					  : sizeof(efi_config_table_32_t);
	}
	return NULL;
}

struct boot_params *bootparams_init(efi_system_table_t *sys_table_arg)
{
	efi_status_t status;
	struct boot_params *p;
	unsigned char sig[8] = {'B', 'P', 'I', '0', '1', '0', '0', '2'};

	status = efi_call_early(allocate_pool, EFI_RUNTIME_SERVICES_DATA,
			SZ_64K, (void **)&p);
	if (status != EFI_SUCCESS)
		return NULL;

	memset(p, 0, SZ_64K);
	memcpy(&p->signature, sig, sizeof(long));

	return p;
}

static unsigned long convert_priv_cmdline(efi_system_table_t *sys_table_arg,
		char *cmdline_ptr, unsigned long rd_addr, unsigned long rd_size,
		unsigned int *pargc, char ***pargv)
{
	efi_status_t status;
	unsigned int argc;
	unsigned int rdprev_size;
	unsigned int cmdline_size;
	char convert_str[CMDLINE_MAX_SIZE];
	char *pstr, *substr;
	char **argv;
	char *tmp_ptr = NULL;

	cmdline_size = strlen(cmdline_ptr);
	snprintf(cmdline_mmap_array, CMDLINE_MAX_SIZE, "vmlinuz.efi ");

	tmp_ptr = strstr(cmdline_ptr, "initrd=");
	if (!tmp_ptr) {
		snprintf(cmdline_mmap_array, CMDLINE_MAX_SIZE,
				"vmlinuz.efi %s", cmdline_ptr);
		pr_efi(sys_table_arg, "Warning: no 'initrd=' option!\n");
		goto completed;
	}
	snprintf(convert_str, CMDLINE_MAX_SIZE,
			" initrd=0x%lx,0x%lx", rd_addr, rd_size);
	rdprev_size = cmdline_size - strlen(tmp_ptr);
	strncat(cmdline_mmap_array, cmdline_ptr, rdprev_size);

	cmdline_ptr = strnstr(tmp_ptr, " ", CMDLINE_MAX_SIZE);
	strcat(cmdline_mmap_array, convert_str);
	if (!cmdline_ptr)
		goto completed;

	strcat(cmdline_mmap_array, cmdline_ptr);

completed:
	status = efi_high_alloc(sys_table_arg, (MAX_ARG_COUNT + 1)
			* (sizeof(char *)), 0, (unsigned long *)&argv,
			EFI_MAX_VALID_MEMORY);
	if (status != EFI_SUCCESS) {
		pr_efi_err(sys_table_arg, "%s: alloc argv mmap_array error\n");
		return status;
	}

	argc = 0;
	pstr = cmdline_mmap_array;

	substr = strsep(&pstr, " \t");
	while (substr != NULL) {
		if (strlen(substr)) {
			argv[argc++] = substr;
			if (argc == MAX_ARG_COUNT) {
				pr_efi_err(sys_table_arg, "argv mmap_array full!\n");
				break;
			}
		}
		substr = strsep(&pstr, " \t");
	}

	*pargc = argc;
	*pargv = argv;

	return EFI_SUCCESS;
}

unsigned int efi_memmap_sort(struct priv_mmap *bpmem,
		unsigned int index, unsigned int mem_type)
{
	unsigned int i, t;
	unsigned long tsize;

	for (i = 0; i < map_entry[mem_type];) {
		tsize = mmap_array[mem_type][i].mem_size;
		for (t = i + 1; t < map_entry[mem_type]; t++) {
			if (mmap_array[mem_type][i].mem_start + tsize ==
					mmap_array[mem_type][t].mem_start) {
				tsize += mmap_array[mem_type][t].mem_size;
			} else {
				break;
			}
		}
		bpmem->map[index].mem_type = mem_type;
		bpmem->map[index].mem_start = mmap_array[mem_type][i].mem_start;
		bpmem->map[index].mem_size = tsize;
		bpmem->map[index].attribute = mmap_array[mem_type][i].attribute;
		i = t;
		index++;
	}
	return index;
}

struct exit_boot_struct {
	int *runtime_entry_count;
	struct boot_params *bp;
};

static efi_status_t mk_mmap(efi_system_table_t *sys_table_arg,
		struct efi_boot_memmap *map, struct boot_params *p)
{
	char checksum;
	unsigned int i;
	unsigned int nr_desc;
	unsigned int mem_type;
	unsigned long tmp_count;
	efi_memory_desc_t *mem_desc;
	struct priv_mmap *mhp = NULL;

	if (!strncmp((char *)p, "BPI", 3)) {
		p->systemtable = sys_table_arg;
		p->flags |= BPI_FLAGS_UEFI_SUPPORTED;
		p->ext_location.ext_offset = sizeof(*p) + sizeof(unsigned long);
		mhp = (struct priv_mmap *)((char *)p
				+ p->ext_location.ext_offset);

		memcpy(&mhp->header.signature, "MEM", sizeof(unsigned long));
		mhp->header.length = sizeof(*mhp);
		mhp->desc_ver = *map->desc_ver;
	}
	if (!(*(map->map_size)) || !(*(map->desc_size)) || !mhp) {
		pr_efi_err(sys_table_arg, "get memory info error\n");
		return EFI_ERROR;
	}
	nr_desc = *(map->map_size) / *(map->desc_size);
	/*
	 * According to UEFI SPEC,mmap_buf is the accurate Memory Map mmap_array \
	 * now we can fill platform specific memory structure.
	 */
	for (i = 0; i < nr_desc; i++) {
		mem_desc = (efi_memory_desc_t *)((char *)(*map->map)
				+ (i * (*(map->desc_size))));
		switch (mem_desc->type) {
		case EFI_RESERVED_TYPE:
		case EFI_RUNTIME_SERVICES_CODE:
		case EFI_RUNTIME_SERVICES_DATA:
		case EFI_MEMORY_MAPPED_IO:
		case EFI_MEMORY_MAPPED_IO_PORT_SPACE:
		case EFI_UNUSABLE_MEMORY:
		case EFI_PAL_CODE:
			mem_type = ADDRESS_TYPE_RESERVED;
			break;

		case EFI_ACPI_MEMORY_NVS:
			mem_type = ADDRESS_TYPE_NVS;
			break;

		case EFI_ACPI_RECLAIM_MEMORY:
			mem_type = ADDRESS_TYPE_ACPI;
			break;

		case EFI_LOADER_CODE:
		case EFI_LOADER_DATA:
		case EFI_PERSISTENT_MEMORY:
		case EFI_BOOT_SERVICES_CODE:
		case EFI_BOOT_SERVICES_DATA:
		case EFI_CONVENTIONAL_MEMORY:
			mem_type = ADDRESS_TYPE_SYSRAM;
			break;

		default:
			continue;
		}

		mmap_array[mem_type][map_entry[mem_type]].mem_type = mem_type;
		mmap_array[mem_type][map_entry[mem_type]].mem_start =
			(mem_desc->phys_addr) & ((1UL << 48) - 1);
		mmap_array[mem_type][map_entry[mem_type]].mem_size =
			mem_desc->num_pages << EFI_PAGE_SHIFT;
		mmap_array[mem_type][map_entry[mem_type]].attribute =
			mem_desc->attribute;
		map_entry[mem_type]++;
	}
	tmp_count = mhp->map_count;
	/* Sort EFI memmap and add to BPI for kernel */
	for (i = 0; i < LOONGSON3_BOOT_MEM_MAP_MAX; i++) {
		if (map_entry[i] == 0)
			continue;
		tmp_count = efi_memmap_sort(mhp, tmp_count, i);
	}

	mhp->map_count = tmp_count;
	mhp->header.checksum = 0;

	checksum = efi_crc8((char *)mhp, mhp->header.length);
	mhp->header.checksum = checksum;

	return EFI_SUCCESS;
}

static efi_status_t exit_boot_func(efi_system_table_t *sys_table_arg,
		struct efi_boot_memmap *map, void *priv)
{
	efi_status_t status;
	struct exit_boot_struct *p = priv;

	status = mk_mmap(sys_table_arg, map, p->bp);
	if (status != EFI_SUCCESS) {
		pr_efi_err(sys_table_arg, "make kernel memory map failed!\n");
		return status;
	}

	return EFI_SUCCESS;
}

static efi_status_t exit_boot_services(efi_system_table_t *sys_table_arg,
		struct boot_params *boot_params, void *handle)
{
	unsigned long map_sz, key, desc_size, buff_size;
	efi_memory_desc_t *mem_map;
	efi_status_t status;
	__u32 desc_version;
	int runtime_entry_count = 0;
	struct efi_boot_memmap map;
	struct exit_boot_struct priv;

	map.map			= &mem_map;
	map.map_size		= &map_sz;
	map.desc_size		= &desc_size;
	map.desc_ver		= &desc_version;
	map.key_ptr		= &key;
	map.buff_size		= &buff_size;

	status = efi_get_memory_map(sys_table_arg, &map);
	if (status != EFI_SUCCESS) {
		pr_efi_err(sys_table_arg, "Unable to retrieve UEFI memory map.\n");
		return status;
	}

	priv.bp = boot_params;
	priv.runtime_entry_count = &runtime_entry_count;

	/* Might as well exit boot services now */
	status = efi_exit_boot_services(sys_table_arg, handle, &map,
			&priv, exit_boot_func);
	if (status != EFI_SUCCESS)
		return status;

	return EFI_SUCCESS;
}

/*
 * EFI entry point for the LoongArch EFI stub.
 */
unsigned long efi_stub_entry(void *handle, efi_system_table_t *sys_table_arg,
		int *argc, char ***argv, struct boot_params **p)
{
	efi_status_t status;
	unsigned int cmdline_size = 0;
	unsigned long initrd_addr = 0;
	unsigned long initrd_size = 0;
	char *cmdline_ptr = NULL;
	enum efi_secureboot_mode secure_boot;
	efi_loaded_image_t *image;

	efi_guid_t loaded_image_proto = LOADED_IMAGE_PROTOCOL_GUID;

	/* Check if we were booted by the EFI firmware */
	if (sys_table_arg->hdr.signature != EFI_SYSTEM_TABLE_SIGNATURE)
		goto fail;
	/*
	 * Get a handle to the loaded image protocol.  This is used to get
	 * information about the running image, such as size and the command
	 * line.
	 */
	status = sys_table_arg->boottime->handle_protocol(handle,
					&loaded_image_proto, (void *)&image);
	if (status != EFI_SUCCESS) {
		pr_efi_err(sys_table_arg, "Failed to get loaded image protocol\n");
		goto fail;
	}

	/* Get the command line from EFI, using the LOADED_IMAGE protocol. */
	cmdline_ptr = efi_convert_cmdline(sys_table_arg, image, &cmdline_size);
	if (!cmdline_ptr) {
		pr_efi_err(sys_table_arg, "getting command line failed!\n");
		goto fail_free_cmdline;
	}

	if (IS_ENABLED(CONFIG_CMDLINE_EXTEND) ||
	    IS_ENABLED(CONFIG_CMDLINE_FORCE) ||
	    cmdline_size == 0)
		efi_parse_options(CONFIG_CMDLINE);

	if (!IS_ENABLED(CONFIG_CMDLINE_FORCE) && cmdline_size > 0)
		efi_parse_options(cmdline_ptr);

	pr_efi(sys_table_arg, "Booting Linux Kernel...\n");

	/* Ask the firmware to clear memory on unclean shutdown */
	efi_enable_reset_attack_mitigation(sys_table_arg);
	secure_boot = efi_get_secureboot(sys_table_arg);

	status = handle_cmdline_files(sys_table_arg, image, cmdline_ptr,
			"initrd=", EFI_MAX_VALID_MEMORY, (unsigned long *)&initrd_addr,
			(unsigned long *)&initrd_size);
	if (status != EFI_SUCCESS) {
		pr_efi_err(sys_table_arg, "Failed get initrd addr!\n");
		goto failed_free;
	}

	status = convert_priv_cmdline(sys_table_arg, cmdline_ptr,
			initrd_addr, initrd_size, argc, argv);
	if (status != EFI_SUCCESS) {
		pr_efi_err(sys_table_arg, "Covert cmdline failed!\n");
		goto failed_free;
	}

	*p = bootparams_init(sys_table_arg);
	if (*p == NULL) {
		pr_efi_err(sys_table_arg, "Create bpi struct error!\n");
		goto fail;
	}

	status = exit_boot_services(sys_table_arg, *p, handle);
	if (status != EFI_SUCCESS) {
		pr_efi_err(sys_table_arg, "exit_boot services failed!\n");
		goto failed_free;
	}


	return EFI_SUCCESS;

failed_free:
	efi_free(sys_table_arg, initrd_size, initrd_addr);

fail_free_cmdline:
	efi_free(sys_table_arg, cmdline_size, (unsigned long)cmdline_ptr);

fail:
	return status;
}
