/* SPDX-License-Identifier: GPL-2.0 */
/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2020 Loongson Technology Corporation Limited
 *
 */
#ifndef _LOONGARCH_DMA_DIRECT_H
#define _LOONGARCH_DMA_DIRECT_H 1

static inline bool dma_capable(struct device *dev, dma_addr_t addr, size_t size)
{
	if (!dev->dma_mask)
		return false;

	return addr + size - 1 <= *dev->dma_mask;
}

dma_addr_t __phys_to_dma(struct device *dev, phys_addr_t paddr);
phys_addr_t __dma_to_phys(struct device *dev, dma_addr_t daddr);

#endif /* _LOONGARCH_DMA_DIRECT_H */
