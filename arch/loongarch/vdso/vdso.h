/*
 * Copyright (C) 2020 Loongson Technology Corporation Limited
 * Authors: Huacai Chen (chenhuacai@loongson.cn)
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */

#include <asm/abidefs.h>

#if _LOONGARCH_SIM != _LOONGARCH_SIM_ABILP64 && defined(CONFIG_64BIT)

/* Building 32-bit VDSO for the 64-bit kernel. Fake a 32-bit Kconfig. */
#undef CONFIG_64BIT
#define CONFIG_32BIT 1
#ifndef __ASSEMBLY__
#include <asm-generic/atomic64.h>
#endif
#endif

#ifndef __ASSEMBLY__

#include <asm/asm.h>
#include <asm/page.h>
#include <asm/vdso.h>

static inline unsigned long get_vdso_base(void)
{
	unsigned long addr;

	/*
	 * We can't use cpu_has_loongarch_r6 since it needs the cpu_data[]
	 * kernel symbol.
	 */
	/*
	 * Get the base load address of the VDSO. We have to avoid generating
	 * relocations and references to the GOT because ld.so does not peform
	 * relocations on the VDSO. We use the current offset from the VDSO base
	 * and perform a PC-relative branch which gives the absolute address in
	 * ra, and take the difference. The assembler chokes on
	 * "li.w %0, _start - .", so embed the offset as a word and branch over
	 * it.
	 *
	 */

	__asm__(
	"	bl	1f				\n"
	"	.word	_start - .			\n"
	"1:	ld.w	%0, $ra, 0		\n"
	"	" STR(PTR_ADDU) " %0, $ra, %0		\n"
	: "=r" (addr)
	:
	: "ra");

	return addr;
}

static inline const union loongarch_vdso_data *get_vdso_data(void)
{
	return (const union loongarch_vdso_data *)(get_vdso_base() - PAGE_SIZE);
}

#endif /* __ASSEMBLY__ */
