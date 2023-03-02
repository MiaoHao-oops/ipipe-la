/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 Loongson Technology Co., Ltd.
 */
#ifndef _ASM_LOONGARCH_EFI_H
#define _ASM_LOONGARCH_EFI_H
#include <linux/efi.h>
extern void __init efi_init(void);
extern void __init efi_runtime_init(void);

#define ARCH_EFI_IRQ_FLAGS_MASK  0x00000001  /*bit0: CP0 Status.IE*/

static inline void efifb_setup_from_dmi(struct screen_info *si, const char *opt)
{
}

#define arch_efi_call_virt_setup()               \
({                                               \
})

#define arch_efi_call_virt(p, f, args...)        \
({                                               \
	efi_##f##_t * __f;                       \
	efi_runtime_services_t * __p;		\
	__p = (efi_runtime_services_t *)TO_CAC((unsigned long)p);	\
	__f = __p->f;                              \
	__f = (efi_##f##_t *)TO_CAC((unsigned long)__f);	\
	__f(args);                               \
})

#define arch_efi_call_virt_teardown()            \
({                                               \
})

#define efi_call_early(f, ...)		sys_table_arg->boottime->f(__VA_ARGS__)
#define __efi_call_early(f, ...)	f(__VA_ARGS__)
#define efi_call_runtime(f, ...)	sys_table_arg->runtime->f(__VA_ARGS__)
#define efi_is_64bit()			(true)

#define efi_table_attr(table, attr, inst) (inst->attr)

#define efi_call_proto(protocol, f, instance, ...)			\
	(((protocol##_t *)instance)->f(instance, ##__VA_ARGS__))

#define EFI_ALLOC_ALIGN		SZ_64K
#define MTLB_ENTRY_FIX_INDEX 0x800
#define EFI_MAX_VALID_MEMORY	0xFF000000

#endif /* _ASM_LOONGARCH_EFI_H */
