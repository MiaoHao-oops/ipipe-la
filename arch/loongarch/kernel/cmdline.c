// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 Loongson Technology Corporation Limited
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/string.h>

#include <asm/addrspace.h>
#include <asm/fw.h>

int fw_argc;
long *_fw_argv, *_fw_envp;

void __init fw_init_cmdline(void)
{
	int i;

	fw_argc = fw_arg0;
	_fw_argv = (long *)TO_CAC(fw_arg1);
#ifdef CONFIG_RUN_ON_QEMU
	_fw_envp = (long *)TO_CAC(fw_arg2);
#else
	_fw_envp = (long *)fw_arg2;
#endif
	arcs_cmdline[0] = '\0';
	for (i = 1; i < fw_argc; i++) {
#ifdef CONFIG_RUN_ON_QEMU
		strlcat(arcs_cmdline, (char*)TO_CAC((unsigned long)fw_argv(i)), COMMAND_LINE_SIZE);
#else
		strlcat(arcs_cmdline, fw_argv(i), COMMAND_LINE_SIZE);
#endif
		if (i < (fw_argc - 1))
			strlcat(arcs_cmdline, " ", COMMAND_LINE_SIZE);
	}
}

