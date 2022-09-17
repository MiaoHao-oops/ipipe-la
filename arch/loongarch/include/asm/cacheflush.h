/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 Loongson Technology Corporation Limited
 */
#ifndef _ASM_CACHEFLUSH_H
#define _ASM_CACHEFLUSH_H

#include <linux/mm.h>
#include <asm/cpu-features.h>
#include <asm/cacheops.h>

#define ARCH_IMPLEMENTS_FLUSH_DCACHE_PAGE 0

extern void local_flush_icache_range(unsigned long start, unsigned long end);

#define flush_icache_range	local_flush_icache_range
#define flush_icache_user_range	local_flush_icache_range

extern void copy_to_user_page(struct vm_area_struct *vma,
	struct page *page, unsigned long vaddr, void *dst, const void *src,
	unsigned long len);

extern void copy_from_user_page(struct vm_area_struct *vma,
	struct page *page, unsigned long vaddr, void *dst, const void *src,
	unsigned long len);


#define flush_cache_all()				do { } while (0)
#define flush_cache_mm(mm)				do { } while (0)
#define flush_cache_dup_mm(mm)				do { } while (0)
#define flush_cache_range(vma, start, end)		do { } while (0)
#define flush_cache_page(vma, vmaddr, pfn)		do { } while (0)
#define flush_cache_vmap(start, end)			do { } while (0)
#define flush_cache_vunmap(start, end)			do { } while (0)
#define flush_icache_page(vma, page)			do { } while (0)
#define flush_icache_user_page(vma, page, addr, len)	do { } while (0)
#define flush_dcache_page(page)				do { } while (0)
#define flush_dcache_mmap_lock(mapping)			do { } while (0)
#define flush_dcache_mmap_unlock(mapping)		do { } while (0)

#define cache_op(op,addr)						\
	__asm__ __volatile__(						\
	"	cacop	%0, %1					\n"	\
	:								\
	: "i" (op), "R" (*(unsigned char *)(addr)))

#define __iflush_prologue {
#define __iflush_epilogue }
#define __dflush_prologue {
#define __dflush_epilogue }

static inline void flush_icache_line_indexed(unsigned long addr)
{
	__iflush_prologue
	cache_op(Index_Invalidate_I, addr);
	__iflush_epilogue
}

static inline void flush_dcache_line_indexed(unsigned long addr)
{
	__dflush_prologue
	cache_op(Index_Writeback_Inv_D, addr);
	__dflush_epilogue
}

static inline void flush_icache_line(unsigned long addr)
{
	__iflush_prologue
	cache_op(Hit_Invalidate_I, addr);
	__iflush_epilogue
}

static inline void flush_dcache_line(unsigned long addr)
{
	__dflush_prologue
	cache_op(Hit_Writeback_Inv_D, addr);
	__dflush_epilogue
}

#endif /* _ASM_CACHEFLUSH_H */
