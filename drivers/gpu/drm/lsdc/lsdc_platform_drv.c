// SPDX-License-Identifier: GPL-2.0+
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
#include <linux/module.h>
#include <linux/platform_device.h>

#include <drm/drm_print.h>
#include <drm/drm_drv.h>

#include <drm/drm_atomic_helper.h>
#include <drm/drm_crtc_helper.h>

#include "lsdc_drv.h"

static const struct lsdc_chip_desc dc_in_ls2k1000 = {
	.chip = LSDC_CHIP_2K1000,
	.num_of_crtc = LSDC_MAX_CRTC,
	/* ls2k1000 user manual say the pix clock can be about 200MHz */
	.max_pixel_clk = 200000,
	.max_width = 4096,
	.max_height = 4096,
	.hw_cursor_w = 32,
	.hw_cursor_h = 32,
};


static const struct lsdc_chip_desc dc_in_ls2k0500 = {
	.chip = LSDC_CHIP_2K0500,
	.num_of_crtc = LSDC_MAX_CRTC,
	.max_pixel_clk = 200000,
	.max_width = 4096,
	.max_height = 4096,
	.hw_cursor_w = 32,
	.hw_cursor_h = 32,
};


static const struct lsdc_platform_desc ls2k1000_pc_general = {
	.ip = &dc_in_ls2k1000,
	.board = LS2K1000_PC_EVB_V1_2,
	.output_desc = {
		{
			.id = 0,
			.desciption = "adv7125",
			.enc_type = DRM_MODE_ENCODER_DAC,
			.con_type = DRM_MODE_CONNECTOR_VGA,
			.i2c_id = 0,
		},
		{
			.id = 1,
			.desciption = "tfp410",
			.enc_type = DRM_MODE_ENCODER_TMDS,
			.con_type = DRM_MODE_CONNECTOR_DVII,
			.i2c_id = 1,
		},
	},
};


static const struct lsdc_platform_desc ls2k1000_pc_evb_v1_1 = {
	.ip = &dc_in_ls2k1000,
	.board = LS2K1000_PC_EVB_V1_1,
	.output_desc = {
		{
			.id = 0,
			.desciption = "tfp410",
			.enc_type = DRM_MODE_ENCODER_TMDS,
			.con_type = DRM_MODE_CONNECTOR_DVII,
			.i2c_id = 0,
		},
		{
			.id = 1,
			.desciption = "tfp410",
			.enc_type = DRM_MODE_ENCODER_TMDS,
			.con_type = DRM_MODE_CONNECTOR_DVII,
			.i2c_id = 1,
		},
	},
};


static const struct lsdc_platform_desc ls2k1000_pc_evb_v1_2 = {
	.ip = &dc_in_ls2k1000,
	.board = LS2K1000_PC_EVB_V1_2,
	.output_desc = {
		{
			.id = 0,
			.desciption = "adv7125",
			.enc_type = DRM_MODE_ENCODER_DAC,
			.con_type = DRM_MODE_CONNECTOR_VGA,
			.i2c_id = 0,
		},
		{
			.id = 1,
			.desciption = "tfp410",
			.enc_type = DRM_MODE_ENCODER_TMDS,
			.con_type = DRM_MODE_CONNECTOR_DVII,
			.i2c_id = 1,
		},
	},
};


static const struct lsdc_platform_desc ls2k1000_pai_udb_v1_5 = {
	.ip = &dc_in_ls2k1000,
	.board = LS2K1000_PAI_UDB_V1_5,
	.output_desc = {
		{
			.id = 0,
			.desciption = "forlinx RGB panel,1024x600,DE",
			.enc_type = DRM_MODE_ENCODER_NONE,
			.con_type = DRM_MODE_CONNECTOR_Unknown,
			.i2c_id = -1, /* -1 for not exist */
		},
		{
			.id = 1,
			.desciption = "sil9022 hdmi transmitor",
			.enc_type = DRM_MODE_ENCODER_TMDS,
			.con_type = DRM_MODE_CONNECTOR_HDMIA,
			.i2c_id = 1,
		},
	},
};

/* zhuoyi mini box */
static const struct lsdc_platform_desc ls2k1000_l72_mb_va = {
	.ip = &dc_in_ls2k1000,
	.board = LS2K1000_L72_MB_VA,
	.output_desc = {
		{
			.id = 0,
			.desciption = "GM7123C",
			.enc_type = DRM_MODE_ENCODER_DAC,
			.con_type = DRM_MODE_CONNECTOR_VGA,
			.i2c_id = 0,
		},
		{
			.id = 1,
			.desciption = "LT8618SXB",
			.enc_type = DRM_MODE_ENCODER_TMDS,
			.con_type = DRM_MODE_CONNECTOR_HDMIA,
			.i2c_id = 1,
		},
	},
};

static const struct lsdc_platform_desc ls2k500_pc_general = {
	.ip = &dc_in_ls2k0500,
	.board = LS2K500_PC_EVB_V1_0,
	.output_desc = {
		{
			.id = 0,
			.desciption = "vga,builtin",
			.enc_type = DRM_MODE_ENCODER_DAC,
			.con_type = DRM_MODE_CONNECTOR_VGA,
			.i2c_id = -1,
		},
		{
			.id = 1,
			.desciption = "tfp410",
			.enc_type = DRM_MODE_ENCODER_TMDS,
			.con_type = DRM_MODE_CONNECTOR_DVII,
			.i2c_id = -1,
		},
	},
};



int lsdc_detect_platform_chip(struct loongson_drm_device *ldev)
{
	struct device_node *np;
	const char *name = NULL;

	for_each_compatible_node(np, NULL, "loongson,ls2k") {
		const char *model = NULL;

		if (!of_device_is_available(np))
			continue;

		of_property_read_string(np, "compatible", &name);

		if (!name)
			continue;

		of_property_read_string(np, "model", &model);
		if (!model) {
			ldev->desc = &ls2k1000_pc_general;
			DRM_WARN("Board type not found\n");
		} else if (!strncmp(model,
				    "loongson,LS2K1000_PC_EVB_V1_2", 29)) {
			ldev->desc = &ls2k1000_pc_evb_v1_2;
			DRM_INFO("LS2K1000_PC_EVB_V1_2 found\n");
		} else if (!strncmp(model,
				    "loongson,LS2K1000_PC_EVB_V1_1", 29)) {
			ldev->desc = &ls2k1000_pc_evb_v1_1;
			DRM_INFO("LS2K1000_PC_EVB_V1_1 found\n");
		} else if (!strncmp(model,
				    "loongson,LS2K1000_PAI_UDB_V1_5", 30)) {
			ldev->desc = &ls2k1000_pai_udb_v1_5;
			DRM_INFO("LS2K1000_PAI_UDB_V1_5 found\n");
		} else if (!strncmp(model,
				    "loongson,LS2K1000_L72_MB_VA", 27)) {
			ldev->desc = &ls2k1000_l72_mb_va;
			DRM_INFO("LS2K1000_L72_MB_VA found\n");
		} else if (!strncmp(model,
				    "loongson,2k500", 27)) {
			ldev->desc = &ls2k500_pc_general;
			/* ls2k0500 don't have a dc pll */
			ldev->dc_pll = NULL;
			DRM_INFO("LS2K500_PC found\n");
		} else
			ldev->desc = &ls2k1000_pc_general;


		DRM_INFO("Loongson 2K series SoC detected.\n");

		of_node_put(np);

		break;
	}

	return 0;
}




static int lsdc_platform_probe(struct platform_device *pdev)
{
	int ret;
	struct drm_device *ddev;
	struct loongson_drm_device *ldev;
	struct resource *res;

	ret = dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(32));
	if (ret) {
		dev_err(&pdev->dev, "Failed to set the DMA mask\n");
		return ret;
	}

	ldev = devm_kzalloc(&pdev->dev,
			sizeof(struct loongson_drm_device), GFP_KERNEL);
	if (ldev == NULL)
		return -ENOMEM;

	lsdc_detect_platform_chip(ldev);

	if ((ldev->desc == NULL) || (ldev->desc->ip == NULL)) {
		DRM_ERROR("unknown dc chip core\n");
		return -ENOENT;
	}

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);

	ldev->reg_base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(ldev->reg_base)) {
		DRM_ERROR("Unable to get lsdc registers\n");
		return PTR_ERR(ldev->reg_base);
	}


	ldev->irq = platform_get_irq(pdev, 0);
	if (ldev->irq < 0) {
		DRM_ERROR("failed to get irq\n");
		return -ENODEV;
	}


	/* Allocate and initialize the driver private structure. */
	ddev = drm_dev_alloc(&loongson_drm_driver, &pdev->dev);
	if (IS_ERR(ddev))
		return PTR_ERR(ddev);

	ret = lsdc_mode_config_init(ddev, ldev);
	if (ret) {
		drm_dev_put(ddev);
		devm_kfree(&pdev->dev, ldev);
	}

	return ret;
}


static int lsdc_platform_remove(struct platform_device *pdev)
{
	struct drm_device *ddev = dev_get_drvdata(&pdev->dev);
	struct loongson_drm_device *ldev = to_loongson_private(ddev);

	if (ldev) {
		devm_kfree(&pdev->dev, ldev);
		ldev = NULL;
	}

	lsdc_mode_config_fini(ddev);

	return 0;
}


#ifdef CONFIG_PM

static int lsdc_drm_suspend(struct device *dev)
{
	struct drm_device *ddev = dev_get_drvdata(dev);

	return drm_mode_config_helper_suspend(ddev);
}

static int lsdc_drm_resume(struct device *dev)
{
	struct drm_device *ddev = dev_get_drvdata(dev);

	return drm_mode_config_helper_resume(ddev);
}

#endif

static SIMPLE_DEV_PM_OPS(lsdc_pm_ops, lsdc_drm_suspend, lsdc_drm_resume);


static const struct of_device_id lsdc_dt_ids[] = {
	{ .compatible = "loongson,display-subsystem", },
	{ .compatible = "loongson,ls-fb", },
	{}
};


struct platform_driver lsdc_platform_driver = {
	.probe = lsdc_platform_probe,
	.remove = lsdc_platform_remove,
	.driver = {
		.name = "lsdc",
		.pm = &lsdc_pm_ops,
		.of_match_table = of_match_ptr(lsdc_dt_ids),
	},
};

MODULE_DEVICE_TABLE(of, lsdc_dt_ids);
