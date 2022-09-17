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
#include <drm/drm_atomic.h>
#include <drm/drm_gem_cma_helper.h>
#include <drm/drm_plane_helper.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_fb_cma_helper.h>

#include "lsdc_drv.h"
#include "lsdc_regs.h"
#include "lsdc_cursor.h"


#define to_lsdc_cursor_plane(ptr)               \
		container_of(ptr, struct lsdc_cursor_plane, plane)

#define LSDC_CURS_MIN_SIZE                      1
#define LSDC_CURS_MAX_SIZE                      64


static const uint32_t lsdc_cursor_supported_formats[] = {
	DRM_FORMAT_ARGB8888,
};


static int lsdc_plane_get_default_zpos(enum drm_plane_type type)
{
	switch (type) {
	case DRM_PLANE_TYPE_PRIMARY:
		return 0;
	case DRM_PLANE_TYPE_OVERLAY:
		return 1;
	case DRM_PLANE_TYPE_CURSOR:
		return 7;
	}
	return 0;
}


/**
 * @lsdc_cursor_destroy:
 *
 * Clean up plane resources. This is only called at driver unload time
 * through drm_mode_config_cleanup() since a plane cannot be hotplugged
 * in DRM.
 */
static void lsdc_cursor_destroy(struct drm_plane *plane)
{
	drm_plane_helper_disable(plane, NULL);
	drm_plane_cleanup(plane);

	DRM_DEBUG_DRIVER("%s\n", __func__);
}


/**
 * @lsdc_plane_reset:
 *
 * Reset plane hardware and software state to off. This function isn't
 * called by the core directly, only through drm_mode_config_reset().
 *
 * Atomic drivers can use drm_atomic_helper_plane_reset() to reset
 * atomic state using this hook.
 */
static void lsdc_plane_reset(struct drm_plane *plane)
{
	drm_atomic_helper_plane_reset(plane);
	plane->state->zpos = lsdc_plane_get_default_zpos(plane->type);

	DRM_DEBUG_DRIVER("%s\n", __func__);
}



static const struct drm_plane_funcs lsdc_cursor_plane_helpers_funcs = {
	.update_plane = drm_atomic_helper_update_plane,
	.disable_plane = drm_atomic_helper_disable_plane,
	.destroy = lsdc_cursor_destroy,
	.reset = lsdc_plane_reset,
	.atomic_duplicate_state = drm_atomic_helper_plane_duplicate_state,
	.atomic_destroy_state = drm_atomic_helper_plane_destroy_state,
};


static int lsdc_cursor_atomic_check(struct drm_plane *plane,
				    struct drm_plane_state *state)
{
	struct drm_crtc *crtc = state->crtc;
	struct drm_crtc_state *crtc_state;
	int dst_x, dst_y;
	int src_w, src_h;

	/* no need for further checks if the plane is being disabled */
	if (!crtc || !state->fb)
		return 0;

	crtc_state = drm_atomic_get_crtc_state(state->state, crtc);

	dst_x = state->crtc_x;
	dst_y = state->crtc_y;

	/* src_x are in 16.16 format */
	src_w = state->src_w >> 16;
	src_h = state->src_h >> 16;

	if (src_w < LSDC_CURS_MIN_SIZE ||
	    src_h < LSDC_CURS_MIN_SIZE ||
	    src_w > LSDC_CURS_MAX_SIZE ||
	    src_h > LSDC_CURS_MAX_SIZE) {
		DRM_ERROR("Invalid cursor size (%dx%d)\n", src_w, src_h);
		return -EINVAL;
	}

	return 0;
}


static void lsdc_cursor_atomic_update(struct drm_plane *plane,
				      struct drm_plane_state *oldstate)
{
	struct loongson_drm_device *ldev = to_loongson_private(plane->dev);
	struct drm_plane_state *state = plane->state;
	struct drm_crtc *crtc = state->crtc;
	struct drm_gem_cma_object *cursor_obj;
	int dst_x, dst_y;
	unsigned int width, height;

	u32 cursor_ctrl;

	if (!crtc || !state->fb)
		return;

	/* Left position of visible portion of plane on crtc */
	dst_x = state->crtc_x;
	/* Upper position of visible portion of plane on crtc */
	dst_y = state->crtc_y;

	if (dst_x < 0)
		dst_x = 0;

	if (dst_y < 0)
		dst_y = 0;

	cursor_obj = drm_fb_cma_get_gem_obj(state->fb, 0);

	width = state->src_w >> 16;
	height = state->src_h >> 16;

	lsdc_reg_write32(ldev, LSDC_CURSOR_ADDR_REG, cursor_obj->paddr);

	/* update the position of the cursor */
	lsdc_reg_write32(ldev, LSDC_CURSOR_POSITION_REG, (dst_y << 16) | dst_x);

	/* cursor format */
	cursor_ctrl = CURSOR_FORMAT_ARGB8888;

	/* Update the location of the cursor */
	/* Place the hardware cursor on the top of CRTC-1 */
	if (drm_crtc_index(crtc))
		cursor_ctrl |= CURSOR_LOCATION_BIT;

	lsdc_reg_write32(ldev, LSDC_CURSOR_CFG_REG, cursor_ctrl);
}


static void lsdc_cursor_atomic_disable(struct drm_plane *plane,
				       struct drm_plane_state *oldstate)
{
	struct loongson_drm_device *ldev = to_loongson_private(plane->dev);

	if (!oldstate->crtc) {
		DRM_DEBUG_DRIVER("drm plane:%d not enabled\n",
				 plane->base.id);
		return;
	}

	lsdc_reg_write32(ldev, LSDC_CURSOR_CFG_REG, 0);

	DRM_DEBUG_KMS("%s disabled\n", plane->name);
}


static const struct drm_plane_helper_funcs lsdc_cursor_helpers_funcs = {
	.atomic_check = lsdc_cursor_atomic_check,
	.atomic_update = lsdc_cursor_atomic_update,
	.atomic_disable = lsdc_cursor_atomic_disable,
};



static void lsdc_plane_init_property(struct drm_plane *plane,
				     enum drm_plane_type type)
{
	int zpos = lsdc_plane_get_default_zpos(type);

	switch (type) {
	case DRM_PLANE_TYPE_PRIMARY:
	case DRM_PLANE_TYPE_OVERLAY:
		drm_plane_create_zpos_property(plane, zpos, 0, 6);
		break;
	case DRM_PLANE_TYPE_CURSOR:
		drm_plane_create_zpos_immutable_property(plane, zpos);
		break;
	}

	drm_plane_create_alpha_property(plane);
}



struct drm_plane *lsdc_create_cursor_plane(struct drm_device *ddev,
					   unsigned int index,
					   unsigned int possible_crtcs)
{
	struct lsdc_cursor_plane *curp;
	int ret;

	curp = devm_kzalloc(ddev->dev, sizeof(*curp), GFP_KERNEL);
	if (!curp) {
		DRM_ERROR("Failed to allocate memory for cursor\n");
		return NULL;
	}

	ret = drm_universal_plane_init(
				ddev,
				&curp->plane,
				possible_crtcs,
				&lsdc_cursor_plane_helpers_funcs,
				lsdc_cursor_supported_formats,
				ARRAY_SIZE(lsdc_cursor_supported_formats),
				NULL, DRM_PLANE_TYPE_CURSOR, NULL);
	if (ret) {
		DRM_ERROR("Failed to initialize universal plane\n");
		goto err_plane;
	}

	curp->id = index;
	curp->showed = false;

	drm_plane_helper_add(&curp->plane, &lsdc_cursor_helpers_funcs);

	lsdc_plane_init_property(&curp->plane, DRM_PLANE_TYPE_CURSOR);

	return &curp->plane;

err_plane:
	devm_kfree(ddev->dev, curp);

	return NULL;
}
