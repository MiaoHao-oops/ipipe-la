// SPDX-License-Identifier: GPL-2.0
#include <linux/efi.h>
#include <asm/efi.h>
#include <asm/sections.h>

typedef void (*kernel_entry_t)(int argc, char **argv, struct boot_params *bp_point);

extern void decompress_kernel(unsigned long boot_heap_start);
extern unsigned long efi_stub_entry(void *handle, efi_system_table_t *sys_table_arg,
		int *argc, char ***argv, struct boot_params **bpp);

static unsigned char efi_heap[BOOT_HEAP_SIZE];

#define csrw64(sel, value)	\
do {	\
		__asm__ __volatile__(	\
			"csrwr\t%z0, " #sel "\n\t"	\
			: : "Jr" (value));	\
} while (0)

efi_status_t start(void *handle, efi_system_table_t *sys_table)
{
	int argc;
	char **argv;
	efi_status_t status;
	struct boot_params *bp_point;
	kernel_entry_t kernel_entry = (kernel_entry_t)KERNEL_ENTRY;

	/* clear BSS */
	memset(_edata, 0, _end - _edata);

	status = efi_stub_entry(handle, sys_table, &argc, &argv, &bp_point);
	if (status != EFI_SUCCESS)
		return status;

	csrw64(0x180, CSR_DMW0_INIT);
	csrw64(0x181, CSR_DMW1_INIT);

	decompress_kernel((unsigned long)efi_heap);

	kernel_entry(argc, argv, bp_point);

	/* unreachable */
	return -1;
}
