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

#include <linux/errno.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/console.h>
#include <linux/pci.h>

#include <drm/drmP.h>
#include <drm/drm_plane.h>

#include <drm/drm_fb_helper.h>
#include <drm/drm_crtc_helper.h>
#include <drm/drm_gem_cma_helper.h>
#include <drm/drm_fb_cma_helper.h>
#include <drm/drm_gem_framebuffer_helper.h>
#include <drm/drm_atomic_helper.h>

#include "lsdc_drv.h"
#include "lsdc_irq.h"
#include "lsdc_crtc.h"
#include "lsdc_plane.h"
#include "lsdc_encoder.h"
#include "lsdc_connector.h"
#include "lsdc_cursor.h"

#include "lsdc_pll.h"

int lsdc_modeset = -1;
MODULE_PARM_DESC(modeset, "Enable/disable CMA-based KMS(1 = enabled, 0 = disabled(default))");
module_param_named(modeset, lsdc_modeset, int, 0644);

int lsdc_shadowfb = -1;
MODULE_PARM_DESC(shadowfb, "Enable/disable dirty update(1 = enabled, 0 = disabled(default))");
module_param_named(shadowfb, lsdc_shadowfb, int, 0644);

int lsdc_ddc0 = -1;
MODULE_PARM_DESC(ddc0, "Enable/disable ddc0(0 = disabled)");
module_param_named(ddc0, lsdc_ddc0, int, 0644);

int lsdc_ddc1 = -1;
MODULE_PARM_DESC(ddc1, "Enable/disable ddc1(0 = disabled)");
module_param_named(ddc1, lsdc_ddc1, int, 0644);

int lsdc_gamma = -1;
MODULE_PARM_DESC(gamma, "enable gamma (-1 = disabled (default), >0 = enabled)");
module_param_named(gamma, lsdc_gamma, int, 0644);

void lsdc_fb_dirty_update_impl(void __iomem *dst,
			       void *vaddr,
			       struct drm_framebuffer * const fb,
			       struct drm_clip_rect * const clip)
{
	const unsigned int cpp = fb->format->cpp[0];
	const unsigned int offset = clip->y1 * fb->pitches[0] + clip->x1 * cpp;
	const size_t len = (clip->x2 - clip->x1) * cpp;
	const unsigned int lines = clip->y2 - clip->y1;
	unsigned int y;

	vaddr += offset;
	dst += offset;
	for (y = 0; y < lines; y++) {
		memcpy_toio(dst, vaddr, len);
		vaddr += fb->pitches[0];
		dst += fb->pitches[0];
	}
}


/*
 * lsdc_fb_dirty() - flushed damage to the display hardware
 *
 * Callback for the dirty fb IOCTL.
 *
 * Userspace can notify the driver via this callback that an area of the
 * framebuffer has changed and should be flushed to the display hardware.
 */
static int lsdc_fb_dirty(struct drm_framebuffer *fb,
			 struct drm_file *file_priv,
			 unsigned int flags,
			 unsigned int color,
			 struct drm_clip_rect *clips,
			 unsigned int num_clips)
{
	struct loongson_drm_device *ldev = to_loongson_private(fb->dev);
	struct drm_gem_cma_object *cma_obj = drm_fb_cma_get_gem_obj(fb, 0);
	struct drm_plane *plane;
	unsigned int i;

	/* fbdev can flush even when we're not interested */
	drm_for_each_plane(plane, fb->dev) {

		drm_modeset_lock(&plane->mutex, NULL);

		if (plane->state->fb == fb) {
			mutex_lock(&ldev->dirty_lock);

			for (i = 0; i < num_clips; ++i)
				lsdc_fb_dirty_update_impl(ldev->vram,
					cma_obj->vaddr, fb, &clips[i]);

			mutex_unlock(&ldev->dirty_lock);
		}

		drm_modeset_unlock(&plane->mutex);
	}

	return 0;
}



static const struct drm_framebuffer_funcs lsdc_gem_fb_funcs = {
	.destroy	= drm_gem_fb_destroy,
	.create_handle	= drm_gem_fb_create_handle,
	.dirty		= lsdc_fb_dirty,
};

/**
 * lsdc_gem_fb_create() - creates a new framebuffer object
 * The ADDFB2 IOCTL calls into this callback.
 *
 * @dev: DRM device
 * @file: DRM file that holds the GEM handle(s) backing the framebuffer
 * @mode_cmd: Metadata from the userspace framebuffer creation request
 *
 * This function creates a new framebuffer object described by
 * &drm_mode_fb_cmd2. This description includes handles for the buffer(s)
 * backing the framebuffer.
 *
 * If your hardware has special alignment or pitch requirements these
 * should be checked before calling this function. The function does
 * buffer size validation.
 *
 * Returns:
 * Pointer to a &drm_framebuffer on success or an error pointer on failure.
 */
static struct drm_framebuffer *lsdc_gem_fb_create(
				struct drm_device *dev,
				struct drm_file *file,
				const struct drm_mode_fb_cmd2 *mode_cmd)
{

	DRM_DEBUG("%s: fb_id=%u, %ux%u\n",
		__func__, mode_cmd->fb_id, mode_cmd->width, mode_cmd->height);

	/* enable dirty update only when user want it. */
	if (lsdc_shadowfb <= 0)
		return drm_gem_fb_create(dev, file, mode_cmd);

	return drm_gem_fb_create_with_funcs(dev,
					    file,
					    mode_cmd,
					    &lsdc_gem_fb_funcs);
}


static const struct drm_mode_config_funcs lsdc_mode_funcs = {
	.fb_create = lsdc_gem_fb_create,
	.output_poll_changed = drm_fb_helper_output_poll_changed,
	.atomic_check = drm_atomic_helper_check,
	.atomic_commit = drm_atomic_helper_commit,
};


static int lsdc_create_outputs(struct drm_device *ddev,
				const uint32_t num_crtc)
{
	struct loongson_drm_device *ldev = to_loongson_private(ddev);
	unsigned int i;

	for (i = 0; i < num_crtc; ++i) {
		struct drm_connector *connector;
		struct drm_encoder *encoder;

		connector = lsdc_connector_init(ddev, i);
		if (PTR_ERR(connector) == -EPROBE_DEFER)
			return -EPROBE_DEFER;
		else if (connector == NULL) {
			DRM_ERROR("Init connector-%d failed.\n", i);
			return -1;
		}

		encoder = lsdc_encoder_init(ddev, i);
		if (encoder == NULL) {
			DRM_ERROR("loongson_encoder_init failed.\n");
			return -1;
		}

		drm_connector_attach_encoder(connector, encoder);

		ldev->num_output++;
	}

	DRM_INFO("Total %d outputs\n", ldev->num_output);

	return 0;
}


static int lsdc_modeset_init(struct drm_device *ddev, const uint32_t num_crtc)
{
	struct device_node *ports;
	unsigned int i = 0;
	int ret;

	ports = of_get_child_by_name(ddev->dev->of_node, "ports");
	if (ports == NULL) {
		/* happens on ls7a1000 platform or when old dtb is in use */
		DRM_INFO("no dtb or no endpoints in dtb\n");

		/* fallback to old solution */
		ret = lsdc_create_outputs(ddev, num_crtc);
		if (ret)
			return ret;
	} else {
		ret = lsdc_attach_bridges(ddev, ports);
		of_node_put(ports);

		if (ret)
			return ret;

		DRM_INFO("all bridges successful attached\n");
	}


	for (i = 0; i < num_crtc; i++) {
		struct drm_plane *primary;
		struct drm_plane *cursor;
		struct lsdc_pll *pixpll;

		pixpll = lsdc_create_pix_pll(ddev, i);
		if (IS_ERR(pixpll)) {
			DRM_ERROR("failed to init fb plane.\n");
			return -ENOMEM;
		}

		primary = lsdc_primary_plane_init(ddev, i);
		if (primary == NULL) {
			DRM_ERROR("failed to init fb plane.\n");
			return -ENOMEM;
		}

		cursor = lsdc_create_cursor_plane(ddev, i, BIT(i));
		if (cursor == NULL) {
			DRM_ERROR("failed to init cursor plane.\n");
			return -ENOMEM;
		}

		ret = lsdc_crtc_init(ddev, i, pixpll, primary, cursor);
	}

	/*
	 * This functions calls all the crtc's, encoder's and connector's
	 * ->reset callback. Drivers can use this in e.g. their driver load
	 * or resume code to reset hardware and software state.
	 */
	drm_mode_config_reset(ddev);

	return 0;
}


#ifdef CONFIG_DEBUG_FS
static int lsdc_show_clock(struct seq_file *m, void *arg)
{
	struct drm_info_node *node = (struct drm_info_node *)m->private;
	struct drm_device *ddev = node->minor->dev;
	struct drm_crtc *crtc;

	drm_for_each_crtc(crtc, ddev) {
		struct drm_display_mode *adj = &crtc->state->adjusted_mode;
		struct loongson_crtc *lcrtc = to_loongson_crtc(crtc);
		struct lsdc_pll *pixpll = lcrtc->pix_pll;
		struct lsdc_pll_core_values params;
		unsigned int out_khz;


		out_khz = pixpll->funcs->get_clock_rate(pixpll, &params);

		seq_printf(m, "Display pipe %u: %dx%d\n",
				lcrtc->crtc_id, adj->hdisplay, adj->vdisplay);

		seq_printf(m, "Frequency actually output: %u kHz\n", out_khz);
		seq_printf(m, "Pixel clock required: %d kHz\n", adj->clock);
		seq_printf(m, "diff: %d kHz\n", adj->clock);

		seq_printf(m, "div_ref=%u, loopc=%u, div_out=%u\n",
				params.div_ref, params.loopc, params.div_out);

		seq_printf(m, "hsync_start=%d, hsync_end=%d, htotal=%d\n",
			      adj->hsync_start, adj->hsync_end, adj->htotal);
		seq_printf(m, "vsync_start=%d, vsync_end=%d, vtotal=%d\n\n",
			      adj->vsync_start, adj->vsync_end, adj->vtotal);
	}

	return 0;
}

static int lsdc_show_mm(struct seq_file *m, void *arg)
{
	struct drm_info_node *node = (struct drm_info_node *) m->private;
	struct drm_device *ddev = node->minor->dev;
	struct drm_printer p = drm_seq_file_printer(m);

	drm_mm_print(&ddev->vma_offset_manager->vm_addr_space_mm, &p);
	return 0;
}

static struct drm_info_list lsdc_debugfs_list[] = {
	{ "clocks", lsdc_show_clock, 0 },
	{ "mm",     lsdc_show_mm,   0, NULL },
};

static int lsdc_debugfs_init(struct drm_minor *minor)
{
	drm_debugfs_create_files(lsdc_debugfs_list,
				 ARRAY_SIZE(lsdc_debugfs_list),
				 minor->debugfs_root,
				 minor);
	return 0;
}
#endif

static int lsdc_gem_cma_dumb_create(struct drm_file *file,
				    struct drm_device *dev,
				    struct drm_mode_create_dumb *args)
{
	unsigned int bytes_per_pixel = (args->bpp + 7) / 8;
	unsigned int pitch = bytes_per_pixel * args->width;

	/*
	 * loongson's display controller require the pitch be a multiple
	 * of 256 bytes, which is for optimize dma dma data transfer
	 */
	args->pitch = roundup(pitch, 256);

	return drm_gem_cma_dumb_create_internal(file, dev, args);
}


DEFINE_DRM_GEM_CMA_FOPS(fops);


struct drm_driver loongson_drm_driver = {

	.driver_features = DRIVER_GEM | DRIVER_MODESET | DRIVER_PRIME |
					 DRIVER_ATOMIC,

	.lastclose = drm_fb_helper_lastclose,
	.fops = &fops,

	.dumb_create = lsdc_gem_cma_dumb_create,
	.gem_free_object_unlocked = drm_gem_cma_free_object,
	.gem_vm_ops = &drm_gem_cma_vm_ops,

	.prime_handle_to_fd = drm_gem_prime_handle_to_fd,
	.prime_fd_to_handle = drm_gem_prime_fd_to_handle,

	.gem_prime_import = drm_gem_prime_import,
	.gem_prime_export = drm_gem_prime_export,

	.gem_prime_get_sg_table = drm_gem_cma_prime_get_sg_table,
	.gem_prime_import_sg_table = drm_gem_cma_prime_import_sg_table,
	.gem_prime_vmap = drm_gem_cma_prime_vmap,
	.gem_prime_vunmap = drm_gem_cma_prime_vunmap,
	.gem_prime_mmap = drm_gem_cma_prime_mmap,

#ifdef CONFIG_DEBUG_FS
	.debugfs_init = lsdc_debugfs_init,
#endif

	.name = "lsdc",
	.desc = "LOONGSON DRM Driver",
	.date = "20190831",
	.major = 1,
	.minor = 0,
	.patchlevel = 1,
};


static void lsdc_kick_out_firmware_fb(void)
{
	struct apertures_struct *ap;

	ap = alloc_apertures(1);
	if (!ap)
		return;

	/* Since lsdc is a UMA device, the simplefb node may have been
	 * located anywhere in memory.
	 */
	ap->ranges[0].base = 0;
	ap->ranges[0].size = ~0;

	drm_fb_helper_remove_conflicting_framebuffers(ap, "lsdc-drmfb", false);
	kfree(ap);
}


int lsdc_mode_config_init(struct drm_device *ddev,
			  struct loongson_drm_device *ldev)
{
	const struct lsdc_chip_desc *descp = ldev->desc->ip;
	uint32_t total_crtcs = 0;
	int ret;

	ldev->ddc0 = !!lsdc_ddc0;
	ldev->ddc1 = !!lsdc_ddc1;

	ldev->enable_gamma = lsdc_gamma > 0 ? true : false;

	ldev->dev = ddev;
	dev_set_drvdata(ddev->dev, ddev);
	ddev->dev_private = ldev;

	mutex_init(&ldev->err_lock);
	mutex_init(&ldev->dirty_lock);
	spin_lock_init(&ldev->reglock);

	drm_mode_config_init(ddev);

	ddev->mode_config.funcs = &lsdc_mode_funcs;
	ddev->mode_config.min_width = 1;
	ddev->mode_config.min_height = 1;
	ddev->mode_config.preferred_depth = 24;
	ddev->mode_config.prefer_shadow = 0;

	if (descp) {
		ddev->mode_config.max_width = descp->max_width;
		ddev->mode_config.max_height = descp->max_width;

		ddev->mode_config.cursor_width = descp->hw_cursor_h;
		ddev->mode_config.cursor_height = descp->hw_cursor_h;

		total_crtcs = descp->num_of_crtc;
	} else {
		ddev->mode_config.max_width = 4096;
		ddev->mode_config.max_height = 4096;
		ddev->mode_config.cursor_width = 32;
		ddev->mode_config.cursor_height = 32;

		/* Currently 2 for LS2k1000 and LS7A1000 */
		total_crtcs = 2;
	}

	ddev->mode_config.allow_fb_modifiers = true;

	ret = lsdc_modeset_init(ddev, total_crtcs);
	if (ret)
		goto out_mode_config;


	dev_info(ddev->dev, "irq = %d\n", ldev->irq);

	ret = devm_request_threaded_irq(ddev->dev, ldev->irq,
				lsdc_irq_handler, lsdc_irq_thread,
				IRQF_ONESHOT,
				dev_name(ddev->dev), ddev);
	if (ret) {
		dev_err(ddev->dev, "Failed to register lsdc interrupt\n");
		return ret;
	}

	/* Allow usage of vblank without having to call drm_irq_install */
	ddev->irq_enabled = 1;


	ret = drm_vblank_init(ddev, total_crtcs);
	if (ret) {
		dev_err(ddev->dev,
			"Fatal error during vblank init: %d\n", ret);
		return ret;
	}

	/* Initialize and enable output polling */
	drm_kms_helper_poll_init(ddev);


	lsdc_kick_out_firmware_fb();

	/*
	 * Register the DRM device with the core and the connectors with sysfs.
	 */
	ret = drm_dev_register(ddev, 0);
	if (ret) {
		drm_dev_put(ddev);
		return ret;
	}

	ret = drm_fb_cma_fbdev_init(ddev, 32, 2);

	return ret;

out_mode_config:
	drm_mode_config_cleanup(ddev);

	return ret;
}


void lsdc_mode_config_fini(struct drm_device *ddev)
{
	struct loongson_drm_device *ldev = to_loongson_private(ddev);

	/* disable output polling */
	drm_kms_helper_poll_fini(ddev);

	drm_fb_cma_fbdev_fini(ddev);

	drm_dev_unregister(ddev);

	ddev->irq_enabled = 0;

	devm_free_irq(ddev->dev, ldev->irq, ddev);

	/* shutdown all CRTC, for driver unloading */
	drm_atomic_helper_shutdown(ddev);

	drm_mode_config_cleanup(ddev);

	drm_dev_put(ddev);
}


static int __init lsdc_drm_init(void)
{
	int ret;
#if defined(CONFIG_PCI)
	struct pci_dev *pdev = NULL;

	/* Multi video card workaround */
	while ((pdev = pci_get_class(PCI_CLASS_DISPLAY_VGA << 8, pdev))) {
		if (pdev->vendor != PCI_VENDOR_ID_LOONGSON) {
			DRM_INFO("Discrete graphic card detected, abort.\n");
			return 0;
		}
	}
#endif

	if (vgacon_text_force()) {
		DRM_ERROR("VGACON disables loongson kernel modesetting.\n");
		return -EINVAL;
	}

	ret = platform_driver_register(&lsdc_platform_driver);

#ifdef CONFIG_DRM_LSDC_PCI_DRIVER
	if (lsdc_modeset == 1)
		return pci_register_driver(&lsdc_pci_driver);
#endif

	return ret;
}
module_init(lsdc_drm_init);


static void __exit lsdc_drm_exit(void)
{
	platform_driver_unregister(&lsdc_platform_driver);

#ifdef CONFIG_DRM_LSDC_PCI_DRIVER
	if (lsdc_modeset == 1)
		return pci_unregister_driver(&lsdc_pci_driver);
#endif
}
module_exit(lsdc_drm_exit);


MODULE_AUTHOR("Sui Jingfeng <suijingfeng@loongson.cn>");
MODULE_DESCRIPTION("DRM platform Driver for loongson 2k1000 SoC");
MODULE_LICENSE("GPL v2");
