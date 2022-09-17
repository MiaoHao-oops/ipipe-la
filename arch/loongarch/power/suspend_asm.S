/* SPDX-License-Identifier: GPL-2.0 */
/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Sleep helper for Loongson-3 sleep mode.
 *
 *  Copyright (C) 2020 Loongson Technology Co., Ltd.
 *  Author: Huacai Chen <chenhuacai@loongson.cn>
 */

#include <asm/asm.h>
#include <asm/asmmacro.h>
#include <asm/loongarchregs.h>
#include <asm/stackframe.h>
#include <asm/addrspace.h>

	.extern loongarch_nr_nodes
	.extern loongarch_suspend_addr
	.extern loongarch_pcache_ways
	.extern loongarch_pcache_sets
	.extern loongarch_pcache_linesz
	.extern loongarch_scache_ways
	.extern loongarch_scache_sets
	.extern loongarch_scache_linesz

	.text
	.align	5

/* preparatory stuff */
.macro	SETUP_SLEEP
	addi.d	sp, sp, -PT_SIZE
	st.d	$r1, sp, PT_R1
	st.d	$r2, sp, PT_R2
	st.d	$r3, sp, PT_R3
	st.d	$r4, sp, PT_R4
	st.d	$r5, sp, PT_R5
	st.d	$r6, sp, PT_R6
	st.d	$r7, sp, PT_R7
	st.d	$r8, sp, PT_R8
	st.d	$r9, sp, PT_R9
	st.d	$r10, sp, PT_R10
	st.d	$r11, sp, PT_R11
	st.d	$r20, sp, PT_R20
	st.d	$r21, sp, PT_R21
	st.d	$r22, sp, PT_R22
	st.d	$r23, sp, PT_R23
	st.d	$r24, sp, PT_R24
	st.d	$r25, sp, PT_R25
	st.d	$r26, sp, PT_R26
	st.d	$r27, sp, PT_R27
	st.d	$r28, sp, PT_R28
	st.d	$r29, sp, PT_R29
	st.d	$r30, sp, PT_R30
	st.d	$r31, sp, PT_R31

#ifdef CONFIG_ACPI
	la	t0, acpi_saved_sp
	st.d	sp, t0, 0
#endif
.endm
/* Sleep code for Loongson-3 */
SYM_CODE_START(loongarch_suspend_enter)
	SETUP_SLEEP

	/* a0:address a1:L1_sets a2:L1_ways a3:L1_linesize */
	li.d a0, CSR_DMW1_INIT
	la	t0, loongarch_pcache_sets
	ld.w	a1, t0, 0
	la	t0, loongarch_pcache_ways
	ld.w	a2, t0, 0
	la	t0, loongarch_pcache_linesz
	ld.w	a3, t0, 0
flushL1:
	move  t0, a2
1:	cacop 8, a0, 0
	cacop 9, a0, 0
	addi.d a0, a0, 1
	addi.w t0, t0, -1
	bnez  t0, 1b
	sub.d  a0, a0, a2
	add.d  a0, a0, a3
	addi.w a1, a1, -1
	bnez  a1, flushL1

	/* a0:nr_nodes a1:address a2:L2_sets a3:L2_ways t8:L2_linesize */
	la	t0, loongarch_nr_nodes
	ld.w	a0, t0, 0
	li.d a1, CSR_DMW1_INIT
	la	t0, loongarch_scache_ways
	ld.w	a3, t0, 0
	la	t0, loongarch_scache_linesz
	ld.w	t8, t0, 0
flushL2_all:
	la	t0, loongarch_scache_sets
	ld.w	a2, t0, 0
	li.d t2, 0x100000000000
flushL2_node:
	move   t0, a3
1:	cacop  0xb, a1, 0
	addi.d a1, a1, 1
	addi.w  t0, t0, -1
	bnez   t0, 1b
	sub.d  a1, a1, a3
	add.d  a1, a1, t8
	addi.w  a2, a2, -1
	bnez   a2, flushL2_node
	add.d  a1, a1, t2
	addi.w  a0, a0, -1
	bnez   a0, flushL2_all

	/* setup MTLB, index:0x800, single page size:0x4000 */
	xori	t3, zero, 0xe
	slli.d	t0, t3, CSR_TLBIDX_PS_SHIFT
	li.d	t1, CSR_TLBIDX_PS
	csrxchg t0, t1, LOONGARCH_CSR_TLBIDX
	xori	t0, zero, 0x800
	xori	t1, zero, CSR_TLBIDX_IDX
	csrxchg	t0, t1, LOONGARCH_CSR_TLBIDX
	xori	t0, zero, 0x0
	li.d	t1, CSR_TLBIDX_EHINV
	csrxchg	t0, t1, LOONGARCH_CSR_TLBIDX

	xori    t0, zero, 0x1
	sll.d	t0, t0, t3
	li.d	t1, 0xffffffff8000
	la	t2, loongarch_suspend_addr
	ld.d	t2, t2, 0
	and     t1, t2, t1
	li.d	t2, (CSR_TLBLO0_V | CSR_TLBLO0_WE | CSR_TLBLO0_GLOBAL)
	or	t2, t2, t1
	or	t3, t0, t2
	csrwr	t1, LOONGARCH_CSR_TLBEHI
	csrwr	t2, LOONGARCH_CSR_TLBELO0
	csrwr	t3, LOONGARCH_CSR_TLBELO1
	tlbwr

	/* Pass RA and SP to BIOS, for machines without CMOS RAM */
	addi.d	a1, sp, 0
	la	a0, loongarch_wakeup_start

	la	t0, loongarch_suspend_addr
	ld.d	t0, t0, 0 /* Call BIOS's STR sleep routine */
	jr	t0
	nop
SYM_CODE_END(loongarch_suspend_enter)

.macro  SETUP_WAKEUP

	nop
	ld.d	$r1, sp, PT_R1
	ld.d	$r2, sp, PT_R2
	ld.d	$r3, sp, PT_R3
	ld.d	$r4, sp, PT_R4
	ld.d	$r5, sp, PT_R5
	ld.d	$r6, sp, PT_R6
	ld.d	$r7, sp, PT_R7
	ld.d	$r8, sp, PT_R8
	ld.d	$r9, sp, PT_R9
	ld.d	$r10, sp, PT_R10
	ld.d	$r11, sp, PT_R11
	ld.d	$r20, sp, PT_R20
	ld.d	$r21, sp, PT_R21
	ld.d	$r22, sp, PT_R22
	ld.d	$r23, sp, PT_R23
	ld.d	$r24, sp, PT_R24
	ld.d	$r25, sp, PT_R25
	ld.d	$r26, sp, PT_R26
	ld.d	$r27, sp, PT_R27
	ld.d	$r28, sp, PT_R28
	ld.d	$r29, sp, PT_R29
	ld.d	$r30, sp, PT_R30
	ld.d	$r31, sp, PT_R31
.endm

	/* This is where we return upon wakeup.
	 * Reload all of the registers and return.
	 */
SYM_CODE_START(loongarch_wakeup_start)
	li.d	t0, CSR_DMW0_INIT	# UC, PLV0
	csrwr	t0, LOONGARCH_CSR_DMWIN0
	li.d	t0, CSR_DMW1_INIT	# CA, PLV0
	csrwr	t0, LOONGARCH_CSR_DMWIN1

	la	t0, acpi_saved_sp
	ld.d	sp, t0, 0
	SETUP_WAKEUP
	addi.d	sp, sp, PT_SIZE
	jr	ra
SYM_CODE_END(loongarch_wakeup_start)
