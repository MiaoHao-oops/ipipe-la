// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 Loongson Technology Corporation Limited
 */

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/pagemap.h>
#include <linux/err.h>
#include <linux/sysctl.h>
#include <asm/mman.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>

pte_t *huge_pte_alloc(struct mm_struct *mm, unsigned long addr,
		      unsigned long sz)
{
	pgd_t *pgd;
	pud_t *pud;
	pte_t *pte = NULL;

	pgd = pgd_offset(mm, addr);
	pud = pud_alloc(mm, pgd, addr);
	if (pud)
		pte = (pte_t *)pmd_alloc(mm, pud, addr);

	return pte;
}

pte_t *huge_pte_offset(struct mm_struct *mm, unsigned long addr,
		       unsigned long sz)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd = NULL;

	pgd = pgd_offset(mm, addr);
	if (pgd_present(*pgd)) {
		pud = pud_offset(pgd, addr);
		if (pud_present(*pud))
			pmd = pmd_offset(pud, addr);
	}
	return (pte_t *) pmd;
}

/*
 * This function checks for proper alignment of input addr and len parameters.
 */
int is_aligned_hugepage_range(unsigned long addr, unsigned long len)
{
	if (len & ~HPAGE_MASK)
		return -EINVAL;
	if (addr & ~HPAGE_MASK)
		return -EINVAL;
	return 0;
}

int pmd_huge(pmd_t pmd)
{
	return (pmd_val(pmd) & _PAGE_HUGE) != 0;
}
EXPORT_SYMBOL(pmd_huge);

int pud_huge(pud_t pud)
{
	return (pud_val(pud) & _PAGE_HUGE) != 0;
}
EXPORT_SYMBOL(pud_huge);

uint64_t pmd_to_entrylo(unsigned long pmd_val)
{
	uint64_t val;
	/* PMD as PTE. Must be huge page */
	if (!pmd_huge(__pmd(pmd_val)))
		panic("%s", __func__);

	val = pmd_val ^ _PAGE_HUGE;
	val |= ((val & _PAGE_HGLOBAL) >>
		(_PAGE_HGLOBAL_SHIFT - _PAGE_GLOBAL_SHIFT));

	return val;
}
