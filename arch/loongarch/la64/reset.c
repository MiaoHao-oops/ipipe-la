// SPDX-License-Identifier: GPL-2.0
/*
 * Author: Huacai Chen, chenhuacai@loongson.cn
 * Copyright (C) 2020 Loongson Technology Co., Ltd.
 */
#include <linux/acpi.h>
#include <linux/cpu.h>
#include <linux/delay.h>
#include <linux/efi.h>
#include <linux/init.h>
#include <linux/kexec.h>
#include <linux/pm.h>
#include <linux/slab.h>
#include <acpi/reboot.h>
#include <asm/bootinfo.h>
#include <asm/delay.h>
#include <asm/idle.h>
#include <asm/page.h>
#include <asm/reboot.h>
#include <boot_param.h>


static void loongson_poweroff(void)
{
#ifdef CONFIG_EFI
	efi.reset_system(EFI_RESET_SHUTDOWN, EFI_SUCCESS, 0, NULL);
#endif
	while (1) {
		cpu_wait();
	}
}

static void loongson_restart(void)
{
	if (efi_capsule_pending(NULL)) {
		pr_info("EFI capsule is pending, forcing EFI reboot.\n");
		efi_reboot(REBOOT_WARM, NULL);
	}

	if (!acpi_disabled)
		acpi_reboot();

	efi_reboot(REBOOT_COLD, NULL);

	while (1) {
		cpu_wait();
	}
}

#ifdef CONFIG_KEXEC

#define MAX_ARGS	64
#define KEXEC_CTRL_CODE	TO_CAC(0x100000UL)
#define KEXEC_ARGV_ADDR	TO_CAC(0x108000UL)
#define KEXEC_ARGV_SIZE	COMMAND_LINE_SIZE

static int kexec_argc;
static int kdump_argc;
static void *kexec_argv;
static void *kdump_argv;

static int loongson_kexec_prepare(struct kimage *image)
{
	int i, argc = 0;
	long offt;
	unsigned long *argv;
	char *str, *ptr, *bootloader = "kexec";

	/* argv at offset 0, argv[] at offset KEXEC_ARGV_SIZE/2 */
	if (image->type == KEXEC_TYPE_DEFAULT)
		argv = (unsigned long *)kexec_argv;
	else
		argv = (unsigned long *)kdump_argv;

	argv[argc++] = (unsigned long)(KEXEC_ARGV_ADDR + KEXEC_ARGV_SIZE/2);

	for (i = 0; i < image->nr_segments; i++) {
		if (!strncmp(bootloader, (char *)image->segment[i].buf,
				strlen(bootloader))) {
			/*
			 * convert command line string to array
			 * of parameters (as bootloader does).
			 */
			str = (char *)argv + KEXEC_ARGV_SIZE/2;
			memcpy(str, image->segment[i].buf, KEXEC_ARGV_SIZE/2);
			ptr = strchr(str, ' ');

			while (ptr && (argc < MAX_ARGS)) {
				*ptr = '\0';
				if (ptr[1] != ' ') {
					offt = (long)(ptr - str + 1);
					argv[argc++] = fw_arg1 + KEXEC_ARGV_SIZE/2 + offt;
				}
				ptr = strchr(ptr + 1, ' ');
			}
			break;
		}
	}

	if (image->type == KEXEC_TYPE_DEFAULT)
		kexec_argc = argc;
	else
		kdump_argc = argc;

	/* kexec/kdump need a safe page to save reboot_code_buffer */
	image->control_code_page = virt_to_page((void *)KEXEC_CTRL_CODE);

	return 0;
}

static void loongson_kexec_shutdown(void)
{
	int cpu;

	memcpy((void *)fw_arg1, kexec_argv, COMMAND_LINE_SIZE);

	kexec_args[0] = kexec_argc;
	kexec_args[1] = fw_arg1;
	kexec_args[2] = fw_arg2;
#ifdef CONFIG_SMP
	secondary_kexec_args[0] = TO_UNCAC(0x1fe01000);

	for_each_possible_cpu(cpu)
		if (!cpu_online(cpu))
			cpu_up(cpu); /* Everyone should go to reboot_code_buffer */
#endif
}

static void loongson_crash_shutdown(struct pt_regs *regs)
{
	default_machine_crash_shutdown(regs);
	kexec_args[0] = kdump_argc;
	kexec_args[1] = fw_arg1;
	kexec_args[2] = fw_arg2;
#ifdef CONFIG_SMP
	secondary_kexec_args[0] = TO_UNCAC(0x1fe01000);
#endif
	memcpy((void *)fw_arg1, kdump_argv, KEXEC_ARGV_SIZE);
}

#endif

static int __init loongarch_reboot_setup(void)
{
	pm_restart = loongson_restart;
	if (loongson_fdt_blob != NULL)
		pm_power_off = NULL;
	else
		pm_power_off = loongson_poweroff;

#ifdef CONFIG_KEXEC
	fw_arg1 = KEXEC_ARGV_ADDR;
	kexec_argv = kmalloc(KEXEC_ARGV_SIZE, GFP_KERNEL);
	kdump_argv = kmalloc(KEXEC_ARGV_SIZE, GFP_KERNEL);

	_machine_kexec_prepare = loongson_kexec_prepare;
	_machine_kexec_shutdown = loongson_kexec_shutdown;
	_machine_crash_shutdown = loongson_crash_shutdown;
#endif

	return 0;
}

arch_initcall(loongarch_reboot_setup);
