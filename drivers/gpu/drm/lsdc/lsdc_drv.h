/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright 2020 Loongson Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sub license, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDERS, AUTHORS AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
 * USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * The above copyright notice and this permission notice (including the
 * next paragraph) shall be included in all copies or substantial portions
 * of the Software.
 */

/*
 * Authors:
 *      Sui Jingfeng <suijingfeng@loongson.cn>
 */


#ifndef __LSDC_DRV_H__
#define __LSDC_DRV_H__

#include <drm/drm_device.h>

#include "lsdc_crtc.h"

#define LSDC_MAX_CRTC           2
#define LSDC_CLUT_SIZE          256

enum loongson_dc_family {
	LSDC_CHIP_UNKNOWN = 0,
	LSDC_CHIP_2K1000 = 1, /* 2-Core SoC, 64-bit */
	LSDC_CHIP_7A1000 = 2, /* North bridges */
	LSDC_CHIP_7A1000_PLUS = 3, /* bandwidth improved */
	LSDC_CHIP_2K0500 = 4, /* Reduced version of 2k1000, single core */
	LSDC_CHIP_7A2000 = 5, /* North bridges */
	LSDC_CHIP_LAST,
};

enum loongson_pc_board_type {
	LS_PCB_UNKNOWN = 0,
	LS2K1000_PC_EVB_V1_1 = 1,
	LS2K1000_PC_EVB_V1_2 = 2,
	LS2K1000_PAI_UDB_V1_5 = 3,
	LS2K1000_L72_MB_VA = 4,
	LS2K500_PC_EVB_V1_0 = 5,
	LS3A4000_7A1000_EVB_BOARD_V1_4 = 6,
	LS3A5000_7A2000_EVB_V1_0 = 7,
};


struct lsdc_output_desc {
	uint32_t id;           /* overall channel index */
	char desciption[32];
	uint32_t enc_type;
	uint32_t con_type;
	int32_t i2c_id;      /* i2c used to probe the monitor */
};

struct lsdc_chip_desc {
	enum loongson_dc_family chip;
	uint32_t num_of_crtc;

	uint32_t max_pixel_clk;

	uint32_t max_width;
	uint32_t max_height;

	uint32_t hw_cursor_w;
	uint32_t hw_cursor_h;
};

/* SoC parameters and board specific information */
struct lsdc_platform_desc {
	const struct lsdc_chip_desc *ip;
	enum loongson_pc_board_type board;
	struct lsdc_output_desc output_desc[LSDC_MAX_CRTC];
};


struct loongson_drm_device {
	struct drm_device *dev;

	void __iomem *reg_base;
	void __iomem *vram;
	resource_size_t vram_base;
	resource_size_t vram_size;

	struct drm_display_mode mode;

	unsigned int num_output;
	struct loongson_crtc *lcrtc[LSDC_MAX_CRTC];

	/* platform specific data */
	const struct lsdc_platform_desc *desc;

	/* PLL of the DC IP core, optional */
	struct lsdc_pll *dc_pll;

	/* @reglock: protects concurrent register access */
	spinlock_t reglock;

	/*
	 * @dirty_lock: Serializes framebuffer flushing
	 */
	struct mutex dirty_lock;

	/*
	 * @err_lock: protecting error_status
	 */
	struct mutex err_lock;

	int irq;
	u32 error_status;
	u32 irq_status;

	/*
	 * @shadowfb: is shadow fb layer is enabled.
	 */
	bool shadowfb;

	/*
	 * @ddc0: false if ddc0 is disabled.
	 */
	bool ddc0;
	/*
	 * @ddc1: false if ddc1 is disabled.
	 */
	bool ddc1;
	/*
	 * @enable_gamma: true if hardware gamma is desired.
	 */
	bool enable_gamma;
};


static inline struct loongson_drm_device *
to_loongson_private(struct drm_device *ddev)
{
	return ddev->dev_private;
}


int lsdc_mode_config_init(struct drm_device *ddev,
			  struct loongson_drm_device *ldev);
void lsdc_mode_config_fini(struct drm_device *ddev);

void lsdc_fb_dirty_update_impl(void __iomem *dst,
			       void *vaddr,
			       struct drm_framebuffer * const fb,
			       struct drm_clip_rect * const clip);

int lsdc_detect_platform_chip(struct loongson_drm_device *ldev);

extern int lsdc_shadowfb;

extern struct drm_driver loongson_drm_driver;

extern struct platform_driver lsdc_platform_driver;

#ifdef CONFIG_DRM_LSDC_PCI_DRIVER
extern struct pci_driver lsdc_pci_driver;
#endif

#endif
