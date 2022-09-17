/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2016 Imagination Technologies
 * Author: Paul Burton <paul.burton@mips.com>
 * Copyright (C) 2020 Loongson Technology Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */

#ifndef __LOONGARCH_ASM_MACHINE_H__
#define __LOONGARCH_ASM_MACHINE_H__

#include <linux/libfdt.h>
#include <linux/of.h>

struct loongarch_machine {
	const struct of_device_id *matches;
	const void *fdt;
	bool (*detect)(void);
	const void *(*fixup_fdt)(const void *fdt, const void *match_data);
	unsigned int (*measure_hpt_freq)(void);
};

extern long __loongarch_machines_start;
extern long __loongarch_machines_end;

#define LOONGARCH_MACHINE(name)						\
	static const struct loongarch_machine __loongarch_mach_##name		\
		__used __section(.loongarch.machines.init)

#define for_each_loongarch_machine(mach)					\
	for ((mach) = (struct loongarch_machine *)&__loongarch_machines_start;	\
	     (mach) < (struct loongarch_machine *)&__loongarch_machines_end;	\
	     (mach)++)

/**
 * loongarch_machine_is_compatible() - check if a machine is compatible with an FDT
 * @mach: the machine struct to check
 * @fdt: the FDT to check for compatibility with
 *
 * Check whether the given machine @mach is compatible with the given flattened
 * device tree @fdt, based upon the compatibility property of the root node.
 *
 * Return: the device id matched if any, else NULL
 */
static inline const struct of_device_id *
loongarch_machine_is_compatible(const struct loongarch_machine *mach, const void *fdt)
{
	const struct of_device_id *match;

	if (!mach->matches)
		return NULL;

	for (match = mach->matches; match->compatible[0]; match++) {
		if (fdt_node_check_compatible(fdt, 0, match->compatible) == 0)
			return match;
	}

	return NULL;
}

/**
 * struct loongarch_fdt_fixup - Describe a fixup to apply to an FDT
 * @apply: applies the fixup to @fdt, returns zero on success else -errno
 * @description: a short description of the fixup
 *
 * Describes a fixup applied to an FDT blob by the @apply function. The
 * @description field provides a short description of the fixup intended for
 * use in error messages if the @apply function returns non-zero.
 */
struct loongarch_fdt_fixup {
	int (*apply)(void *fdt);
	const char *description;
};

/**
 * apply_loongarch_fdt_fixups() - apply fixups to an FDT blob
 * @fdt_out: buffer in which to place the fixed-up FDT
 * @fdt_out_size: the size of the @fdt_out buffer
 * @fdt_in: the FDT blob
 * @fixups: pointer to an array of fixups to be applied
 *
 * Loop through the array of fixups pointed to by @fixups, calling the apply
 * function on each until either one returns an error or we reach the end of
 * the list as indicated by an entry with a NULL apply field.
 *
 * Return: zero on success, else -errno
 */
extern int __init apply_loongarch_fdt_fixups(void *fdt_out, size_t fdt_out_size,
					const void *fdt_in,
					const struct loongarch_fdt_fixup *fixups);

#endif /* __LOONGARCH_ASM_MACHINE_H__ */
