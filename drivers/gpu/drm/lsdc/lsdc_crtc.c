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

#include <drm/drm_device.h>
#include <drm/drm_crtc.h>
#include <drm/drm_plane.h>
#include <drm/drm_atomic_helper.h>

#include <drm/drm_vblank.h>

#include "lsdc_drv.h"
#include "lsdc_regs.h"
#include "lsdc_plane.h"
#include "lsdc_pll.h"
#include "lsdc_cursor.h"


static int lsdc_crtc_enable_vblank(struct drm_crtc *crtc)
{
	struct loongson_drm_device *ldev = to_loongson_private(crtc->dev);
	struct loongson_crtc *lcrtc = to_loongson_crtc(crtc);
	unsigned int val = lsdc_reg_read32(ldev, LSDC_INT_REG);

	if (lcrtc->crtc_id == 0)
		val |= INT_CRTC0_VS_EN;
	else if (lcrtc->crtc_id == 1)
		val |= INT_CRTC1_VS_EN;
	else
		DRM_ERROR("lsdc crtc is no more than 2\n");

	lsdc_reg_write32(ldev, LSDC_INT_REG, val);

	DRM_DEBUG("CRTC%u: vblank enabled\n", lcrtc->crtc_id);

	return 0;
}


static void lsdc_crtc_disable_vblank(struct drm_crtc *crtc)
{
	struct loongson_drm_device *ldev = to_loongson_private(crtc->dev);
	struct loongson_crtc *lcrtc = to_loongson_crtc(crtc);
	unsigned int val = lsdc_reg_read32(ldev, LSDC_INT_REG);

	if (lcrtc->crtc_id == 0)
		val &= ~INT_CRTC0_VS_EN;
	else if (lcrtc->crtc_id == 1)
		val &= ~INT_CRTC1_VS_EN;
	else
		DRM_ERROR("lsdc crtc is no more than 2\n");

	lsdc_reg_write32(ldev, LSDC_INT_REG, val);

	DRM_DEBUG("CRTC%u: vblank disabled\n", lcrtc->crtc_id);
}


static void lsdc_crtc_destroy(struct drm_crtc *crtc)
{
	struct loongson_drm_device *ldev = to_loongson_private(crtc->dev);
	struct loongson_crtc *lcrtc = to_loongson_crtc(crtc);

	if (lcrtc) {
		devm_kfree(crtc->dev->dev, lcrtc);
		DRM_INFO("%s: CRTC%u destroyed\n", __func__, lcrtc->crtc_id);
		ldev->lcrtc[lcrtc->crtc_id] = NULL;
	}

	drm_crtc_cleanup(crtc);
}


/*
 * CRTC got soft reset if bit 20 of CRTC*_CFG_REG from 1 to 0
 */
void lsdc_crtc_reset(struct drm_crtc *crtc)
{
	struct loongson_drm_device *ldev = to_loongson_private(crtc->dev);
	struct loongson_crtc *lcrtc = to_loongson_crtc(crtc);
	unsigned int crtc_id = lcrtc->crtc_id;
	u32 val = CFG_RESET_BIT;

	if (ldev->enable_gamma)
		val |= CFG_GAMMAR_EN_BIT;

	if (crtc_id == 0) {
		DRM_DEBUG_DRIVER("%s: Reset CRTC0\n", __func__);
		lsdc_reg_write32(ldev, LSDC_CRTC0_CFG_REG, val);
	} else if (crtc_id == 1) {
		DRM_DEBUG_DRIVER("%s: Reset CRTC1\n", __func__);
		lsdc_reg_write32(ldev, LSDC_CRTC1_CFG_REG, val);
	} else
		DRM_ERROR("lsdc crtc is no more than 2\n");

	drm_atomic_helper_crtc_reset(crtc);
}


/**
 * These provide the minimum set of functions required to handle a CRTC
 * Each driver is responsible for filling out this structure at startup time
 *
 * The drm_crtc_funcs structure is the central CRTC management structure
 * in the DRM. Each CRTC controls one or more connectors
 */
static const struct drm_crtc_funcs loongson_crtc_funcs = {
	.reset = lsdc_crtc_reset,
	.gamma_set = drm_atomic_helper_legacy_gamma_set,
	.destroy = lsdc_crtc_destroy,
	.set_config = drm_atomic_helper_set_config,
	.page_flip = drm_atomic_helper_page_flip,
	.atomic_duplicate_state = drm_atomic_helper_crtc_duplicate_state,
	.atomic_destroy_state = drm_atomic_helper_crtc_destroy_state,
	.enable_vblank = lsdc_crtc_enable_vblank,
	.disable_vblank = lsdc_crtc_disable_vblank,
};



static enum drm_mode_status lsdc_crtc_mode_valid(struct drm_crtc *crtc,
					const struct drm_display_mode *mode)
{
	if (mode->hdisplay % 16)
		return MODE_BAD;

	return MODE_OK;
}

/**
 * @lsdc_crtc_mode_set_nofb:
 *
 * This callback is used to update the display mode of a CRTC without
 * changing anything of the primary plane configuration. This fits the
 * requirement of atomic and hence is used by the atomic helpers.
 * It is also used by the transitional plane helpers to implement a
 * @mode_set hook in drm_helper_crtc_mode_set().
 *
 * Note that the display pipe is completely off when this function is called.
 * Atomic drivers which need hardware to be running before they program the
 * new display mode (e.g. because they implement runtime PM) should not use
 * this hook.
 *
 * This is because the helper library calls this hook only once per mode change
 * and not every time the display pipeline is suspended using either DPMS or
 * the new "ACTIVE" property. Which means register values set in this callback
 * might get reset when the CRTC is suspended, but not restored. Such drivers
 * should instead move all their CRTC setup into the @atomic_enable callback.
 *
 * This callback is optional.
 */
static void lsdc_crtc_mode_set_nofb(struct drm_crtc *crtc)
{
	struct loongson_drm_device *ldev = to_loongson_private(crtc->dev);
	struct loongson_crtc *lcrtc = to_loongson_crtc(crtc);
	struct drm_display_mode *mode = &crtc->state->adjusted_mode;
	unsigned int crtc_id = lcrtc->crtc_id;
	struct lsdc_pll *pixpll;
	unsigned int pixclock = mode->clock;
	u32 val;

	if (crtc_id == 0) {
		/* CRTC 0 */
		DRM_DEBUG_DRIVER("CRTC0 mode set no fb\n");

		lsdc_reg_write32(ldev, FB_DITCFG_DVO0_REG, 0);
		lsdc_reg_write32(ldev, FB_DITTAB_LO_DVO0_REG, 0);
		lsdc_reg_write32(ldev, FB_DITTAB_HI_DVO0_REG, 0);
		lsdc_reg_write32(ldev, FB_PANCFG_DVO0_REG, 0x80001311);
		lsdc_reg_write32(ldev, FB_PANTIM_DVO0_REG, 0);

		lsdc_reg_write32(ldev, LSDC_CRTC0_FB_ORIGIN_REG, 0);

		/* hack 256 bytes align issue */
		val = (mode->crtc_hdisplay + 63) & ~63;
		val |= (mode->crtc_htotal << 16);
		lsdc_reg_write32(ldev, FB_HDISPLAY_DVO0_REG, val);

		val = (mode->crtc_vtotal << 16) | mode->crtc_vdisplay;
		lsdc_reg_write32(ldev, FB_VDISPLAY_DVO0_REG, val);


		/* HSync */
		val = CFG_EN_HSYNC;

		/* bits 26:16 hsync end */
		val |= mode->crtc_hsync_end << 16;
		/* bits 10:0 hsync start */
		val |= mode->crtc_hsync_start;

		if (mode->flags & DRM_MODE_FLAG_NHSYNC) {
			val |= CFG_INV_HSYNC;
			DRM_DEBUG_DRIVER("CRTC0 HSync Inverted\n");
		}

		lsdc_reg_write32(ldev, FB_HSYNC_DVO0_REG, val);


		/* VSync */
		val = CFG_EN_VSYNC;

		/* bits 26:16 vsync end */
		val |= mode->crtc_vsync_end << 16;
		/* bits 10:0 vsync start */
		val |= mode->crtc_vsync_start;

		if (mode->flags & DRM_MODE_FLAG_NVSYNC) {
			val |= CFG_INV_VSYNC;
			DRM_DEBUG_DRIVER("CRTC0 VSync Inverted\n");
		}

		lsdc_reg_write32(ldev, FB_VSYNC_DVO0_REG, val);
	} else if (crtc_id == 1) {
		/* CRTC 1 */
		DRM_DEBUG_DRIVER("CRTC1 mode set no fb\n");

		lsdc_reg_write32(ldev, FB_DITCFG_DVO1_REG, 0);
		lsdc_reg_write32(ldev, FB_DITTAB_LO_DVO1_REG, 0);
		lsdc_reg_write32(ldev, FB_DITTAB_HI_DVO1_REG, 0);
		lsdc_reg_write32(ldev, FB_PANCFG_DVO1_REG, 0x80001311);
		lsdc_reg_write32(ldev, FB_PANTIM_DVO1_REG, 0);


		lsdc_reg_write32(ldev, LSDC_CRTC1_FB_ORIGIN_REG, 0);

		/* hack 256 byte align issue */
		val = (mode->crtc_hdisplay + 63) & ~63;
		val |= (mode->crtc_htotal << 16);

		lsdc_reg_write32(ldev, FB_HDISPLAY_DVO1_REG, val);

		lsdc_reg_write32(ldev, FB_VDISPLAY_DVO1_REG,
			(mode->crtc_vtotal << 16) | mode->crtc_vdisplay);


		/* HSYNC */
		val = CFG_EN_HSYNC;

		/* bits 26:16 hsync end */
		val |= mode->crtc_hsync_end << 16;
		/* bits 10:0 hsync start */
		val |= mode->crtc_hsync_start;

		if (mode->flags & DRM_MODE_FLAG_NHSYNC) {
			val |= CFG_INV_HSYNC;
			DRM_DEBUG_DRIVER("CRTC1 HSync Inverted\n");
		}

		lsdc_reg_write32(ldev, FB_HSYNC_DVO1_REG, val);


		/* VSYNC */
		val = CFG_EN_VSYNC;

		/* bits 26:16 vsync end */
		val |= mode->crtc_vsync_end << 16;
		/* bits 10:0 vsync start */
		val |= mode->crtc_vsync_start;

		if (mode->flags & DRM_MODE_FLAG_NVSYNC) {
			val |= CFG_INV_VSYNC;
			DRM_DEBUG_DRIVER("CRTC1 VSync Inverted\n");
		}

		lsdc_reg_write32(ldev, FB_VSYNC_DVO1_REG, val);
	} else
		DRM_DEBUG_DRIVER("CRTC is no more than 2\n");

	/* config the pixel pll */
	pixpll = lcrtc->pix_pll;

	if (pixpll->funcs->find_pll_param(pixpll, pixclock) == false)
		pixpll->funcs->compute_clock(pixpll, pixclock);

	pixpll->funcs->config_pll(pixpll);
}


static void lsdc_crtc_atomic_enable(struct drm_crtc *crtc,
				    struct drm_crtc_state *old_state)
{
	struct loongson_drm_device *ldev = to_loongson_private(crtc->dev);
	struct loongson_crtc *lcrtc = to_loongson_crtc(crtc);
	unsigned int crtc_id = lcrtc->crtc_id;
	u32 val;

	if (crtc_id == 0) {
		val = lsdc_reg_read32(ldev, LSDC_CRTC0_CFG_REG);
		val |= CFG_OUTPUT_ENABLE;
		lsdc_reg_write32(ldev, LSDC_CRTC0_CFG_REG, val);
	} else if (crtc_id == 1) {
		val = lsdc_reg_read32(ldev, LSDC_CRTC1_CFG_REG);
		val |= CFG_OUTPUT_ENABLE;
		lsdc_reg_write32(ldev, LSDC_CRTC1_CFG_REG, val);
	} else
		DRM_ERROR("CRTC is no more than 2\n");

	DRM_DEBUG_DRIVER("%s: CRTC%u enabled\n", __func__, crtc_id);

	drm_crtc_vblank_on(crtc);
}


static void lsdc_crtc_atomic_disable(struct drm_crtc *crtc,
				     struct drm_crtc_state *old_state)
{
	struct loongson_drm_device *ldev = to_loongson_private(crtc->dev);
	struct loongson_crtc *lcrtc = to_loongson_crtc(crtc);
	unsigned int crtc_id = lcrtc->crtc_id;
	u32 val;

	drm_crtc_vblank_off(crtc);

	if (crtc_id == 0) {
		val = lsdc_reg_read32(ldev, LSDC_CRTC0_CFG_REG);
		val &= ~CFG_OUTPUT_ENABLE;
		lsdc_reg_write32(ldev, LSDC_CRTC0_CFG_REG, val);
	} else if (crtc_id == 1) {
		val = lsdc_reg_read32(ldev, LSDC_CRTC1_CFG_REG);
		val &= ~CFG_OUTPUT_ENABLE;
		lsdc_reg_write32(ldev, LSDC_CRTC1_CFG_REG, val);
	} else
		DRM_ERROR("CRTC is no more than 2\n");

	DRM_DEBUG_DRIVER("%s: CRTC%u disabled\n", __func__, crtc_id);
}

static void lsdc_crtc_update_clut(struct drm_crtc *crtc)
{
	struct loongson_drm_device *ldev = to_loongson_private(crtc->dev);
	struct loongson_crtc *lcrtc = to_loongson_crtc(crtc);
	unsigned int crtc_id = lcrtc->crtc_id;
	struct drm_color_lut *lut;
	unsigned int i;

	if (!ldev->enable_gamma)
		return;

	if (!crtc->state->color_mgmt_changed || !crtc->state->gamma_lut)
		return;

	lut = (struct drm_color_lut *)crtc->state->gamma_lut->data;

	lsdc_reg_write32(ldev, LSDC_CRTC0_GAMMA_INDEX_REG, 0);

	for (i = 0; i < LSDC_CLUT_SIZE; i++) {
		u32 val = ((lut->red << 8) & 0xff0000) |
			  (lut->green & 0xff00) |
			  (lut->blue >> 8) ;

		if (crtc_id == 0)
			lsdc_reg_write32(ldev, LSDC_CRTC0_GAMMA_DATA_REG, val);
		else if (crtc_id == 1)
			lsdc_reg_write32(ldev, LSDC_CRTC1_GAMMA_DATA_REG, val);

		lut++;
	}
}

/**
 * @lsdc_crtc_atomic_flush:
 *
 * should finalize an atomic update of multiple planes on a CRTC in this hook.
 * Depending upon hardware this might include checking that vblank evasion
 * was successful, unblocking updates by setting bits or setting the GO bit
 * to flush out all updates.
 *
 * Simple hardware or hardware with special requirements can commit and
 * flush out all updates for all planes from this hook and forgo all the
 * other commit hooks for plane updates.
 *
 * This hook is called after any plane commit functions are called.
 *
 * Note that the power state of the display pipe when this function is
 * called depends upon the exact helpers and calling sequence the driver
 * has picked. See drm_atomic_helper_commit_planes() for a discussion of
 * the tradeoffs and variants of plane commit helpers.
 *
 * This callback is used by the atomic modeset helpers and by the
 * transitional plane helpers, but it is optional.
 */

static void lsdc_crtc_atomic_flush(struct drm_crtc *crtc,
				   struct drm_crtc_state *old_crtc_state)
{
	struct drm_pending_vblank_event *event = crtc->state->event;

	lsdc_crtc_update_clut(crtc);

	if (event) {
		crtc->state->event = NULL;

		spin_lock_irq(&crtc->dev->event_lock);
		if (drm_crtc_vblank_get(crtc) == 0)
			drm_crtc_arm_vblank_event(crtc, event);
		else
			drm_crtc_send_vblank_event(crtc, event);
		spin_unlock_irq(&crtc->dev->event_lock);

		crtc->state->event = NULL;
	}
}


/**
 * These provide the minimum set of functions required to handle a CRTC
 *
 * The drm_crtc_helper_funcs is a helper operations for CRTC
 */
static const struct drm_crtc_helper_funcs lsdc_crtc_helper_funcs = {
	.mode_valid = lsdc_crtc_mode_valid,
	.mode_set_nofb = lsdc_crtc_mode_set_nofb,
	.atomic_enable = lsdc_crtc_atomic_enable,
	.atomic_disable = lsdc_crtc_atomic_disable,
	.atomic_flush = lsdc_crtc_atomic_flush,
};



/**
 * lsdc_crtc_init
 *
 * @ldev: point to the loongson_drm_device structure
 *
 * Init CRTC
 */
int lsdc_crtc_init(struct drm_device *ddev,
		   unsigned int index,
		   struct lsdc_pll *pixpll,
		   struct drm_plane *primary_plane,
		   struct drm_plane *cursor_plane)
{
	struct loongson_drm_device *ldev = to_loongson_private(ddev);
	struct loongson_crtc *lcrtc;
	int ret;

	lcrtc = devm_kzalloc(ddev->dev, sizeof(*lcrtc), GFP_KERNEL);

	lcrtc->crtc_id = index;

	lcrtc->pix_pll = pixpll;

	ret = drm_crtc_init_with_planes(ddev,
			&lcrtc->base,
			primary_plane,
			cursor_plane,
			&loongson_crtc_funcs, NULL);
	if (ret)
		DRM_ERROR("crtc init with planes failed\n");

	ret = drm_mode_crtc_set_gamma_size(&lcrtc->base, LSDC_CLUT_SIZE);
	if (ret)
		DRM_WARN("set the gamma table size failed\n");

	drm_crtc_enable_color_mgmt(&lcrtc->base, 0, false, LSDC_CLUT_SIZE);

	drm_crtc_helper_add(&lcrtc->base, &lsdc_crtc_helper_funcs);

	ldev->lcrtc[index] = lcrtc;

	DRM_INFO("CRTTC%d created\n", index);

	return ret;
}
