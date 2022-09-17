/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 Loongson Technology Corporation Limited
 */
#include <linux/linkage.h>

#include <asm/asm.h>
#include <asm/export.h>
#include <asm/page.h>
#include <asm/regdef.h>
#include <asm/loongarchregs.h>
#include <asm/stackframe.h>
#include <asm/pgtable.h>

	.align 5
SYM_FUNC_START(clear_page)
	lu12i.w  t0, 1 << (PAGE_SHIFT - 12)
	add.d    t0, t0, a0
1:
	st.d     zero, a0, 0
	st.d     zero, a0, 8
	st.d     zero, a0, 16
	st.d     zero, a0, 24
	st.d     zero, a0, 32
	st.d     zero, a0, 40
	st.d     zero, a0, 48
	st.d     zero, a0, 56
	addi.d   a0,   a0,  128
	st.d     zero, a0, -64
	st.d     zero, a0, -56
	st.d     zero, a0, -48
	st.d     zero, a0, -40
	st.d     zero, a0, -32
	st.d     zero, a0, -24
	st.d     zero, a0, -16
	st.d     zero, a0, -8
	bne      t0,   a0, 1b

	jirl     $r0, ra, 0
SYM_FUNC_END(clear_page)
EXPORT_SYMBOL(clear_page)

.align 5
SYM_FUNC_START(copy_page)
	lu12i.w  t8, 1 << (PAGE_SHIFT - 12)
	add.d    t8, t8, a0
1:
	ld.d     t0, a1,  0
	ld.d     t1, a1,  8
	ld.d     t2, a1,  16
	ld.d     t3, a1,  24
	ld.d     t4, a1,  32
	ld.d     t5, a1,  40
	ld.d     t6, a1,  48
	ld.d     t7, a1,  56

	st.d     t0, a0,  0
	st.d     t1, a0,  8
	ld.d     t0, a1,  64
	ld.d     t1, a1,  72
	st.d     t2, a0,  16
	st.d     t3, a0,  24
	ld.d     t2, a1,  80
	ld.d     t3, a1,  88
	st.d     t4, a0,  32
	st.d     t5, a0,  40
	ld.d     t4, a1,  96
	ld.d     t5, a1,  104
	st.d     t6, a0,  48
	st.d     t7, a0,  56
	ld.d     t6, a1,  112
	ld.d     t7, a1,  120
	addi.d   a0, a0,  128
	addi.d   a1, a1,  128

	st.d     t0, a0,  -64
	st.d     t1, a0,  -56
	st.d     t2, a0,  -48
	st.d     t3, a0,  -40
	st.d     t4, a0,  -32
	st.d     t5, a0,  -24
	st.d     t6, a0,  -16
	st.d     t7, a0,  -8

	bne      t8, a0, 1b
	jirl     $r0, ra, 0
SYM_FUNC_END(copy_page)
EXPORT_SYMBOL(copy_page)

SYM_FUNC_START(handle_tlb_modify)
	csrwr	t0, LOONGARCH_CSR_KS0
	csrwr	t1, LOONGARCH_CSR_KS1
	csrwr	$r1, LOONGARCH_CSR_KS2

	/*
	 * The vmalloc handling is not in the hotpath.
	 */
	csrrd	t0, LOONGARCH_CSR_BADV
	blt	t0, $r0, vmalloc_modify
	csrrd	t1, LOONGARCH_CSR_PGDL

vmalloc_done_modify:

	/* get pgd offset in bytes */
	srli.d	t0, t0, PGDIR_SHIFT
	andi	t0, t0, (PTRS_PER_PGD - 1)
	slli.d	t0, t0, 3
	add.d	t1, t1, t0
#if CONFIG_PGTABLE_LEVELS > 3
	csrrd	t0, LOONGARCH_CSR_BADV
	ld.d	t1, t1, 0
	srli.d	t0, t0, PUD_SHIFT
	andi	t0, t0, (PTRS_PER_PUD - 1)
	slli.d	t0, t0, 3
	add.d	t1, t1, t0
#endif
#if CONFIG_PGTABLE_LEVELS > 2
	csrrd	t0, LOONGARCH_CSR_BADV
	ld.d	t1, t1, 0
	srli.d	t0, t0, PMD_SHIFT
	andi	t0, t0, (PTRS_PER_PMD - 1)
	slli.d	t0, t0, 3
	add.d	t1, t1, t0
#endif
	ld.d	$r1, t1, 0

	/*
	 * For huge tlb entries, pmde doesn't contain an address but
	 * instead contains the tlb pte. Check the PAGE_HUGE bit and
	 * see if we need to jump to huge tlb processing.
	 */
	andi	t0, $r1, _PAGE_HUGE
	bne	t0, $r0, tlb_huge_update_modify

	csrrd	t0, LOONGARCH_CSR_BADV
	srli.d	t0, t0, (PAGE_SHIFT + PTE_ORDER)
	andi	t0, t0, (PTRS_PER_PTE - 1)
	slli.d	t0, t0, _PTE_T_LOG2
	add.d	t1, $r1, t0

#ifdef CONFIG_SMP
smp_pgtable_change_modify:
#endif
#ifdef CONFIG_SMP
	ll.d	t0, t1, 0
#else
	ld.d	t0, t1, 0
#endif
	tlbsrch

	srli.d	$r1, t0, _PAGE_WRITE_SHIFT
	andi	$r1, $r1, 1
	beq	$r1, $r0, nopage_tlb_modify


	/* Present and writable bits set, set accessed and dirty bits. */
	ori	t0, t0, (_PAGE_VALID | _PAGE_DIRTY)
#ifdef CONFIG_SMP
	sc.d	t0, t1, 0
	beq	t0, $r0, smp_pgtable_change_modify
#else
	st.d	t0, t1, 0
#endif
	ori	t1, t1, 8
	xori	t1, t1, 8
	ld.d	t0, t1, 0
	ld.d	t1, t1, 8
	csrwr	t0, LOONGARCH_CSR_TLBELO0
	csrwr	t1, LOONGARCH_CSR_TLBELO1
	tlbwr
leave_modify:
	csrrd	t0, LOONGARCH_CSR_KS0
	csrrd	t1, LOONGARCH_CSR_KS1
	csrrd	$r1, LOONGARCH_CSR_KS2
	ertn
#ifdef CONFIG_64BIT
vmalloc_modify:
	la.abs	t1, swapper_pg_dir
	b	vmalloc_done_modify
#endif

	/*
	 * This is the entry point when
	 * build_tlbchange_handler_head spots a huge page.
	 */
tlb_huge_update_modify:
#ifdef CONFIG_SMP
	ll.d	t0, t1, 0
#else
	ld.d	t0, t1, 0
#endif

	srli.d	$r1, t0, _PAGE_WRITE_SHIFT
	andi	$r1, $r1, 1
	beq	$r1, $r0, nopage_tlb_modify

	tlbsrch
	ori	t0, t0, (_PAGE_VALID | _PAGE_DIRTY)

#ifdef CONFIG_SMP
	sc.d	t0, t1, 0
	beq	t0, $r0, tlb_huge_update_modify
	ld.d	t0, t1, 0
#else
	st.d	t0, t1, 0
#endif
	/*
	 * A huge PTE describes an area the size of the
	 * configured huge page size. This is twice the
	 * of the large TLB entry size we intend to use.
	 * A TLB entry half the size of the configured
	 * huge page size is configured into entrylo0
	 * and entrylo1 to cover the contiguous huge PTE
	 * address space.
	 */
	/* Huge page: Move Global bit */
	xori	t0, t0, _PAGE_HUGE
	lu12i.w	t1, _PAGE_HGLOBAL >> 12
	and	t1, t0, t1
	srli.d	t1, t1, (_PAGE_HGLOBAL_SHIFT - _PAGE_GLOBAL_SHIFT)
	or	t0, t0, t1

	addi.d	$r1, t0, 0
	csrwr	t0, LOONGARCH_CSR_TLBELO0
	addi.d	t0, $r1, 0

	/* convert to entrylo1 */
	addi.d	t1, $r0, 1
	slli.d	t1, t1, (HPAGE_SHIFT - 1)
	add.d	t0, t0, t1
	csrwr	t0, LOONGARCH_CSR_TLBELO1

	/* Set huge page tlb entry size */
	addu16i.d	t0, $r0, (PS_MASK >> 16)
	addu16i.d	t1, $r0, (PS_HUGE_SIZE << (PS_SHIFT - 16))
	csrxchg		t1, t0, LOONGARCH_CSR_TLBIDX

	tlbwr

	/* Reset default page size */
	addu16i.d	t0, $r0, (PS_MASK >> 16)
	addu16i.d	t1, $r0, (PS_DEFAULT_SIZE << (PS_SHIFT - 16))
	csrxchg		t1, t0, LOONGARCH_CSR_TLBIDX

nopage_tlb_modify:
	dbar	0
	csrrd	$r1, LOONGARCH_CSR_KS2
	la.abs	t0, tlb_do_page_fault_1
	jirl	$r0, t0, 0
SYM_FUNC_END(handle_tlb_modify)

SYM_FUNC_START(handle_tlb_store)
	csrwr	t0, LOONGARCH_CSR_KS0
	csrwr	t1, LOONGARCH_CSR_KS1
	csrwr	$r1, LOONGARCH_CSR_KS2

	/*
	 * The vmalloc handling is not in the hotpath.
	 */
	csrrd	t0, LOONGARCH_CSR_BADV
	blt	t0, $r0, vmalloc_store
	csrrd	t1, LOONGARCH_CSR_PGDL

vmalloc_done_store:

	/* get pgd offset in bytes */
	srli.d	t0, t0, PGDIR_SHIFT
	andi	t0, t0, (PTRS_PER_PGD - 1)
	slli.d	t0, t0, 3
	add.d	t1, t1, t0

#if CONFIG_PGTABLE_LEVELS > 3
	csrrd	t0, LOONGARCH_CSR_BADV
	ld.d t1, t1, 0
	srli.d	t0, t0, PUD_SHIFT
	andi	t0, t0, (PTRS_PER_PUD - 1)
	slli.d	t0, t0, 3
	add.d	t1, t1, t0
#endif
#if CONFIG_PGTABLE_LEVELS > 2
	csrrd	t0, LOONGARCH_CSR_BADV
	ld.d t1, t1, 0
	srli.d	t0, t0, PMD_SHIFT
	andi	t0, t0, (PTRS_PER_PMD - 1)
	slli.d	t0, t0, 3
	add.d	t1, t1, t0
#endif
	ld.d	$r1, t1, 0

	/*
	 * For huge tlb entries, pmde doesn't contain an address but
	 * instead contains the tlb pte. Check the PAGE_HUGE bit and
	 * see if we need to jump to huge tlb processing.
	 */
	andi	t0, $r1, _PAGE_HUGE
	bne	t0, $r0, tlb_huge_update_store

	csrrd	t0, LOONGARCH_CSR_BADV
	srli.d	t0, t0, (PAGE_SHIFT + PTE_ORDER)
	andi	t0, t0, (PTRS_PER_PTE - 1)
	slli.d	t0, t0, _PTE_T_LOG2
	add.d	t1, $r1, t0

#ifdef CONFIG_SMP
smp_pgtable_change_store:
#endif
#ifdef CONFIG_SMP
	ll.d	t0, t1, 0
#else
	ld.d	t0, t1, 0
#endif
	tlbsrch

	srli.d	$r1, t0, _PAGE_PRESENT_SHIFT
	andi	$r1, $r1, ((_PAGE_PRESENT | _PAGE_WRITE) >> _PAGE_PRESENT_SHIFT)
	xori	$r1, $r1, ((_PAGE_PRESENT | _PAGE_WRITE) >> _PAGE_PRESENT_SHIFT)
	bne	$r1, $r0, nopage_tlb_store

	ori	t0, t0, (_PAGE_VALID | _PAGE_DIRTY)
#ifdef CONFIG_SMP
	sc.d	t0, t1, 0
	beq	t0, $r0, smp_pgtable_change_store
#else
	st.d	t0, t1, 0
#endif

	ori	t1, t1, 8
	xori	t1, t1, 8
	ld.d	t0, t1, 0
	ld.d	t1, t1, 8
	csrwr	t0, LOONGARCH_CSR_TLBELO0
	csrwr	t1, LOONGARCH_CSR_TLBELO1
	tlbwr
leave_store:
	csrrd	t0, LOONGARCH_CSR_KS0
	csrrd	t1, LOONGARCH_CSR_KS1
	csrrd	$r1, LOONGARCH_CSR_KS2
	ertn
#ifdef CONFIG_64BIT
vmalloc_store:
	la.abs	t1, swapper_pg_dir
	b	vmalloc_done_store
#endif

	/*
	 * This is the entry point when build_tlbchange_handler_head
	 * spots a huge page.
	 */
tlb_huge_update_store:
#ifdef CONFIG_SMP
	ll.d	t0, t1, 0
#else
	ld.d	t0, t1, 0
#endif
	srli.d	$r1, t0, _PAGE_PRESENT_SHIFT
	andi	$r1, $r1, ((_PAGE_PRESENT | _PAGE_WRITE) >> _PAGE_PRESENT_SHIFT)
	xori	$r1, $r1, ((_PAGE_PRESENT | _PAGE_WRITE) >> _PAGE_PRESENT_SHIFT)
	bne	$r1, $r0, nopage_tlb_store

	tlbsrch
	ori	t0, t0, (_PAGE_VALID | _PAGE_DIRTY)

#ifdef CONFIG_SMP
	sc.d	t0, t1, 0
	beq	t0, $r0, tlb_huge_update_store
	ld.d	t0, t1, 0
#else
	st.d	t0, t1, 0
#endif
	/* The type conversion is to avoid uasm warning */
	addu16i.d	t1, $r0, -(CSR_TLBIDX_EHINV >> 16)
	addi.d	$r1, t1, 0
	csrxchg	$r1, t1, LOONGARCH_CSR_TLBIDX
	tlbwr

	csrxchg	$r0, t1, LOONGARCH_CSR_TLBIDX
	/*
	 * A huge PTE describes an area the size of the
	 * configured huge page size. This is twice the
	 * of the large TLB entry size we intend to use.
	 * A TLB entry half the size of the configured
	 * huge page size is configured into entrylo0
	 * and entrylo1 to cover the contiguous huge PTE
	 * address space.
	 */
	/* Huge page: Move Global bit */
	xori	t0, t0, _PAGE_HUGE
	lu12i.w	t1, _PAGE_HGLOBAL >> 12
	and	t1, t0, t1
	srli.d	t1, t1, (_PAGE_HGLOBAL_SHIFT - _PAGE_GLOBAL_SHIFT)
	or	t0, t0, t1

	addi.d	$r1, t0, 0
	csrwr	t0, LOONGARCH_CSR_TLBELO0
	addi.d	t0, $r1, 0

	/* convert to entrylo1 */
	addi.d	t1, $r0, 1
	slli.d	t1, t1, (HPAGE_SHIFT - 1)
	add.d	t0, t0, t1
	csrwr	t0, LOONGARCH_CSR_TLBELO1

	/* Set huge page tlb entry size */
	addu16i.d	t0, $r0, (PS_MASK >> 16)
	addu16i.d	t1, $r0, (PS_HUGE_SIZE << (PS_SHIFT - 16))
	csrxchg		t1, t0, LOONGARCH_CSR_TLBIDX

	tlbfill

	/* Reset default page size */
	addu16i.d	t0, $r0, (PS_MASK >> 16)
	addu16i.d	t1, $r0, (PS_DEFAULT_SIZE << (PS_SHIFT - 16))
	csrxchg		t1, t0, LOONGARCH_CSR_TLBIDX

nopage_tlb_store:
	dbar	0
	csrrd	$r1, LOONGARCH_CSR_KS2

	la.abs	t0, tlb_do_page_fault_1

	jirl	$r0, t0, 0
SYM_FUNC_END(handle_tlb_store)

SYM_FUNC_START(handle_tlb_load)
	csrwr	t0, LOONGARCH_CSR_KS0
	csrwr	t1, LOONGARCH_CSR_KS1
	csrwr	$r1, LOONGARCH_CSR_KS2

	/*
	 * The vmalloc handling is not in the hotpath.
	 */
	csrrd	t0, LOONGARCH_CSR_BADV
	blt	t0, $r0, vmalloc_load
	csrrd	t1, LOONGARCH_CSR_PGDL

vmalloc_done_load:

	/* get pgd offset in bytes */
	srli.d	t0, t0, PGDIR_SHIFT
	andi	t0, t0, (PTRS_PER_PGD - 1)
	slli.d	t0, t0, 3
	add.d	t1, t1, t0
#if CONFIG_PGTABLE_LEVELS > 3
	csrrd	t0, LOONGARCH_CSR_BADV
	ld.d	t1, t1, 0
	srli.d	t0, t0, PUD_SHIFT
	andi	t0, t0, (PTRS_PER_PUD - 1)
	slli.d	t0, t0, 3
	add.d	t1, t1, t0
#endif
#if CONFIG_PGTABLE_LEVELS > 2
	csrrd	t0, LOONGARCH_CSR_BADV
	ld.d	t1, t1, 0
	srli.d	t0, t0, PMD_SHIFT
	andi	t0, t0, (PTRS_PER_PMD - 1)
	slli.d	t0, t0, 3
	add.d	t1, t1, t0
#endif
	ld.d	$r1, t1, 0

	/*
	 * For huge tlb entries, pmde doesn't contain an address but
	 * instead contains the tlb pte. Check the PAGE_HUGE bit and
	 * see if we need to jump to huge tlb processing.
	 */
	andi	t0, $r1, _PAGE_HUGE
	bne	t0, $r0, tlb_huge_update_load

	csrrd	t0, LOONGARCH_CSR_BADV
	srli.d	t0, t0, (PAGE_SHIFT + PTE_ORDER)
	andi	t0, t0, (PTRS_PER_PTE - 1)
	slli.d	t0, t0, _PTE_T_LOG2
	add.d	t1, $r1, t0

#ifdef CONFIG_SMP
smp_pgtable_change_load:
#endif
#ifdef CONFIG_SMP
	ll.d	t0, t1, 0
#else
	ld.d	t0, t1, 0
#endif
	tlbsrch

	srli.d	$r1, t0, _PAGE_PRESENT_SHIFT
	andi	$r1, $r1, 1
	beq	$r1, $r0, nopage_tlb_load

	ori	t0, t0, _PAGE_VALID
#ifdef CONFIG_SMP
	sc.d	t0, t1, 0
	beq	t0, $r0, smp_pgtable_change_load
#else
	st.d	t0, t1, 0
#endif
	ori	t1, t1, 8
	xori	t1, t1, 8
	ld.d	t0, t1, 0
	ld.d	t1, t1, 8
	csrwr	t0, LOONGARCH_CSR_TLBELO0
	csrwr	t1, LOONGARCH_CSR_TLBELO1
	tlbwr
leave_load:
	csrrd	t0, LOONGARCH_CSR_KS0
	csrrd	t1, LOONGARCH_CSR_KS1
	csrrd	$r1, LOONGARCH_CSR_KS2
	ertn
#ifdef CONFIG_64BIT
vmalloc_load:
	la.abs	t1, swapper_pg_dir
	b	vmalloc_done_load
#endif

	/*
	 * This is the entry point when build_tlbchange_handler_head
	 * spots a huge page.
	 */
tlb_huge_update_load:
#ifdef CONFIG_SMP
	ll.d	t0, t1, 0
#else
	ld.d	t0, t1, 0
#endif
	srli.d	$r1, t0, _PAGE_PRESENT_SHIFT
	andi	$r1, $r1, 1
	beq	$r1, $r0, nopage_tlb_load
	tlbsrch

	ori	t0, t0, _PAGE_VALID
#ifdef CONFIG_SMP
	sc.d	t0, t1, 0
	beq	t0, $r0, tlb_huge_update_load
	ld.d	t0, t1, 0
#else
	st.d	t0, t1, 0
#endif
	/* The type conversion is to avoid uasm warning */
	addu16i.d	t1, $r0, -(CSR_TLBIDX_EHINV >> 16)
	addi.d		$r1, t1, 0
	csrxchg		$r1, t1, LOONGARCH_CSR_TLBIDX
	tlbwr

	csrxchg		$r0, t1, LOONGARCH_CSR_TLBIDX

	/*
	 * A huge PTE describes an area the size of the
	 * configured huge page size. This is twice the
	 * of the large TLB entry size we intend to use.
	 * A TLB entry half the size of the configured
	 * huge page size is configured into entrylo0
	 * and entrylo1 to cover the contiguous huge PTE
	 * address space.
	 */
	/* Huge page: Move Global bit */
	xori	t0, t0, _PAGE_HUGE
	lu12i.w	t1, _PAGE_HGLOBAL >> 12
	and	t1, t0, t1
	srli.d	t1, t1, (_PAGE_HGLOBAL_SHIFT - _PAGE_GLOBAL_SHIFT)
	or	t0, t0, t1

	addi.d	$r1, t0, 0
	csrwr	t0, LOONGARCH_CSR_TLBELO0
	addi.d	t0, $r1, 0

	/* convert to entrylo1 */
	addi.d	t1, $r0, 1
	slli.d	t1, t1, (HPAGE_SHIFT - 1)
	add.d	t0, t0, t1
	csrwr	t0, LOONGARCH_CSR_TLBELO1

	/* Set huge page tlb entry size */
	addu16i.d	t0, $r0, (PS_MASK >> 16)
	addu16i.d	t1, $r0, (PS_HUGE_SIZE << (PS_SHIFT - 16))
	csrxchg		t1, t0, LOONGARCH_CSR_TLBIDX

	tlbfill

	addu16i.d	t0, $r0, (PS_MASK >> 16)
	addu16i.d	t1, $r0, (PS_DEFAULT_SIZE << (PS_SHIFT - 16))
	csrxchg		t1, t0, LOONGARCH_CSR_TLBIDX
nopage_tlb_load:
	dbar	0
	csrrd	$r1, LOONGARCH_CSR_KS2
	la.abs	t0, tlb_do_page_fault_0
	jirl	$r0, t0, 0
SYM_FUNC_END(handle_tlb_load)

SYM_FUNC_START(handle_tlb_refill)
	csrwr	t0, LOONGARCH_CSR_TLBRSAVE
	csrrd	t0, LOONGARCH_CSR_PGD
	lddir	t0, t0, 3
#if CONFIG_PGTABLE_LEVELS > 2
	lddir	t0, t0, 1
#endif
	ldpte	t0, 0
	ldpte	t0, 1
	tlbfill
	csrrd	t0, LOONGARCH_CSR_TLBRSAVE
	ertn
SYM_FUNC_END(handle_tlb_refill)

	.macro tlb_do_page_fault, write
	SYM_FUNC_START(tlb_do_page_fault_\write)
	SAVE_ALL docfi=0
	csrrd	a2, LOONGARCH_CSR_BADV
	KMODE
	move	a0, sp
	REG_S	a2, sp, PT_BVADDR
	li.w	a1, \write
	la.abs	t0, do_page_fault
	jirl    ra, t0, 0
	la.abs	t0, ret_from_exception
	jirl    zero, t0, 0
	SYM_FUNC_END(tlb_do_page_fault_\write)
	.endm

	tlb_do_page_fault 0
	tlb_do_page_fault 1

SYM_FUNC_START(tlb_do_page_fault_protect)
	csrwr	t0, LOONGARCH_CSR_KS0
	csrwr	t1, LOONGARCH_CSR_KS1
	la.abs	t0, tlb_do_page_fault_0
	jirl	zero, t0, 0
SYM_FUNC_END(tlb_do_page_fault_protect)
