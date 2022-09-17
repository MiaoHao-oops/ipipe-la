// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2020 Loongson Corporation
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
 *	Sui Jingfeng <suijingfeng@loongson.cn>
 */

#include <drm/drm_crtc_helper.h>

#include <drm/drm_of.h>
#include <drm/drm_bridge.h>

#include "lsdc_drv.h"
#include "lsdc_encoder.h"
#include "lsdc_regs.h"


const char *encoder_type_to_string(const unsigned int T)
{
	switch (T) {
	case DRM_MODE_ENCODER_NONE:
		return "NONE";
	case DRM_MODE_ENCODER_DAC:
		return "DAC";
	case DRM_MODE_ENCODER_TMDS:
		return "TMDS";
	case DRM_MODE_ENCODER_LVDS:
		return "LVDS";
	case DRM_MODE_ENCODER_TVDAC:
		return "TVDAC";
	case DRM_MODE_ENCODER_VIRTUAL:
		return "VIRTUAL";
	case DRM_MODE_ENCODER_DSI:
		return "DSI";
	case DRM_MODE_ENCODER_DPMST:
		return "DPMST";
	case DRM_MODE_ENCODER_DPI:
		return "DPI";
	default:
		return "Unknown";
	}
}

static void lsdc_hdmi_init(struct loongson_drm_device *ldev, unsigned int index)
{
	if (index == 0) {
		/* Enable hdmi */
		lsdc_reg_write32(ldev, HDMI0_CTRL_REG, 0x280 | HDMI_EN | HDMI_PACKET_EN);

		/* hdmi zone idle */
		lsdc_reg_write32(ldev, HDMI0_ZONE_REG, 0x00400040);
	} else if (index == 1) {
		/* Enable hdmi */
		lsdc_reg_write32(ldev, HDMI1_CTRL_REG, 0x280 | HDMI_EN | HDMI_PACKET_EN);

		/* hdmi zone idle */
		lsdc_reg_write32(ldev, HDMI1_ZONE_REG, 0x00400040);
	}

	DRM_DEBUG_DRIVER("HDMI%d reset\n", index);
}


static void lsdc_encoder_reset(struct drm_encoder *encoder)
{
	struct loongson_drm_device *ldev = to_loongson_private(encoder->dev);
	int index = encoder->index;

	if (ldev->desc->ip->chip == LSDC_CHIP_7A2000)
		lsdc_hdmi_init(ldev, index);
}

static const struct drm_encoder_funcs lsdc_encoder_funcs = {
	.reset = lsdc_encoder_reset,
	.destroy = drm_encoder_cleanup,
};


static int lsdc_get_encoder_type(struct drm_device *ddev, const unsigned int index)
{
	struct loongson_drm_device *ldev = to_loongson_private(ddev);
	unsigned int enc_type;

	if ((index < 2) && (index >= 0)) {
		enc_type = ldev->desc->output_desc[index].enc_type;

		DRM_DEBUG_KMS("%s: encoder index=%d, type=%s\n",
			__func__, index,
			encoder_type_to_string(enc_type));

		return enc_type;
	}

	DRM_ERROR("%s: encoder index=%d overflow\n", __func__, index);

	return DRM_MODE_ENCODER_NONE;
}


struct drm_encoder *lsdc_encoder_init(struct drm_device *ddev,
				      unsigned int encoder_id)
{
	struct drm_encoder *encoder;
	int ret;

	encoder = devm_kzalloc(ddev->dev, sizeof(*encoder), GFP_KERNEL);
	if (!encoder)
		return ERR_PTR(-ENOMEM);

	encoder->possible_crtcs = BIT(encoder_id);
	encoder->possible_clones = BIT(1) | BIT(0);

	ret = drm_encoder_init(ddev, encoder, &lsdc_encoder_funcs,
		lsdc_get_encoder_type(ddev, encoder_id), NULL);

	if (ret == 0)
		DRM_INFO("%s: Initial encoder %d successful.\n",
			__func__, encoder_id);
	else
		DRM_ERROR("%s: Initial encoder %d failed.\n",
			__func__, encoder_id);

	return encoder;
}



static int lsdc_attach_bridge_to_encoder(struct drm_device *ddev,
					struct drm_bridge *bridge,
					unsigned int port_idx,
					struct drm_encoder **encoder_pp)
{
	struct loongson_drm_device *ldev;
	struct drm_encoder *encoder;
	int ret;

	ldev = to_loongson_private(ddev);
	encoder = devm_kzalloc(ddev->dev, sizeof(*encoder), GFP_KERNEL);
	if (!encoder)
		return -EINVAL;

	ret = drm_encoder_init(ddev, encoder,
			       &lsdc_encoder_funcs,
			       lsdc_get_encoder_type(ddev, port_idx), NULL);
	if (ret)
		return ret;


	encoder->possible_crtcs = BIT(port_idx);

	ret = drm_bridge_attach(encoder, bridge, NULL);
	if (ret == 0) {
		if (encoder_pp)
			*encoder_pp = encoder;
		return 0;
	}

	drm_encoder_cleanup(encoder);

	return ret;
}


static int lsdc_attach_panel_to_encoder(struct drm_device *ddev,
				  struct drm_panel *panel,
				  unsigned int port_idx,
				  struct drm_encoder **encoder_pp)
{
	int ret;
	struct drm_bridge *bridge = NULL;

	bridge = drm_panel_bridge_add(panel, DRM_MODE_CONNECTOR_Unknown);
	if (IS_ERR(bridge))
		return PTR_ERR(bridge);

	ret = lsdc_attach_bridge_to_encoder(ddev, bridge, port_idx, encoder_pp);
	if (ret != 0) {
		DRM_WARN("Failed to attache panel@%d\n", port_idx);
		if (bridge)
			drm_panel_bridge_remove(bridge);
	}

	return ret;
}



int lsdc_attach_bridges(struct drm_device *ddev, struct device_node *ports)
{
	struct loongson_drm_device *ldev = to_loongson_private(ddev);
	unsigned int port_idx;
	int ret;
	/* we need to know if specific output channel is available */
	int status[LSDC_MAX_CRTC] = {0};
	struct drm_bridge *bridge[LSDC_MAX_CRTC] = {NULL};
	struct drm_panel *panel[LSDC_MAX_CRTC] = {NULL};

	ldev->num_output = 0;

	for (port_idx = 0; port_idx < LSDC_MAX_CRTC; port_idx++) {
		/* endpoint can be 0 or -1 */
		status[port_idx] = drm_of_find_panel_or_bridge(ports,
			port_idx, 0, &panel[port_idx], &bridge[port_idx]);

		if (status[port_idx] == -EPROBE_DEFER) {
			DRM_INFO("defer probe at port@%u\n", port_idx);
			return -EPROBE_DEFER;
		}

		DRM_INFO("port@%u found.\n", port_idx);
	}


	for (port_idx = 0; port_idx < LSDC_MAX_CRTC; port_idx++) {
		struct drm_encoder *encoder = NULL;

		if (status[port_idx] == -ENODEV) {
			DRM_WARN("DVO@%u port don't have a output device.\n",
				port_idx);
			continue;
		}

		/* have a panel or bridge */
		if (panel[port_idx]) {
			DRM_INFO("port@%u is a panel.\n", port_idx);
			ret = lsdc_attach_panel_to_encoder(ddev,
					panel[port_idx], port_idx, &encoder);
		} else if (bridge[port_idx]) {
			DRM_INFO("port@%u is a bridge.\n", port_idx);
			ret = lsdc_attach_bridge_to_encoder(ddev,
					bridge[port_idx], port_idx, &encoder);
		}

		if (ret == 0) {
			ldev->num_output++;
			DRM_INFO("%s: port@%d attached.\n", __func__, port_idx);
		} else {
			/* TODO: clean up already initinalized */
			DRM_ERROR("attaching port@%u failed.\n", port_idx);
			return ret;
		}
	}

	if (ldev->num_output == 0) {
		DRM_ERROR("%s: no output device found.\n", __func__);
		return -ENODEV;
	}

	DRM_INFO("Total %d outputs.\n", ldev->num_output);

	/* At least one device was successfully attached.*/
	return 0;
}
