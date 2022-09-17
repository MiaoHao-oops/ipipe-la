/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Arch specific extensions to struct device
 *
 * This file is released under the GPLv2
 * Copyright (C) 2020 Loongson Technology Corporation Limited
 */
#ifndef _ASM_LOONGARCH_DEVICE_H
#define _ASM_LOONGARCH_DEVICE_H

struct dev_archdata {
	unsigned long dma_attrs;
#if defined(CONFIG_LOONGARCH_IOMMU)
	/* hook for IOMMU specific extension */
	void *iommu;
#endif
	bool cpu_device;
};

struct pdev_archdata {
};

struct dma_domain {
	struct list_head node;
	const struct dma_map_ops *dma_ops;
	int domain_nr;
};
void add_dma_domain(struct dma_domain *domain);
void del_dma_domain(struct dma_domain *domain);

#endif /* _ASM_LOONGARCH_DEVICE_H*/
