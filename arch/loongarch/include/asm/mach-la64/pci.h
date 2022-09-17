/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2008 Zhang Le <r0bertz@gentoo.org>
 * Copyright (c) 2009 Wu Zhangjin <wuzhangjin@gmail.com>
 * Copyright (C) 2020 Loongson Technology Co., Ltd.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General
 * Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

#ifndef __ASM_MACH_LOONGSON64_PCI_H_
#define __ASM_MACH_LOONGSON64_PCI_H_

extern struct pci_ops loongson_pci_ops;

/* this is pci memory space */
#define LOONGSON_PCI_MEM_START	0x40000000UL
#define LOONGSON_PCI_MEM_END	0x7fffffffUL

/* this is an offset from io_port_base */
#define LOONGSON_PCI_IO_START	0x00004000UL

#endif /* !__ASM_MACH_LOONGSON64_PCI_H_ */
