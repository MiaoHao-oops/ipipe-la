// SPDX-License-Identifier: GPL-2.0-or-later

#include <drm/drm_encoder.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_crtc_helper.h>
#include <drm/drm_edid.h>
#include "../loongson_drv.h"
#include "../loongson_vbios.h"
#include "../loongson_i2c.h"
#include "gsgpu_dc_device.h"

/*gsgpu connector*/
static struct drm_encoder *best_encoder(struct drm_connector *connector)
{
	int enc_id = connector->encoder_ids[0];
	struct drm_mode_object *obj;
	struct drm_encoder *encoder;

	if (enc_id) {
		obj = drm_mode_object_find(connector->dev, NULL,
		      enc_id, DRM_MODE_OBJECT_ENCODER);
		if (!obj) {
			DRM_ERROR("Couldn't find encoder for our connector\n");
			return NULL;
		}
		encoder = obj_to_encoder(obj);
		return encoder;
	}

	DRM_ERROR("No encoder id\n");

	return NULL;
}

static int gsgpu_dc_connector_get_modes(struct drm_connector *connector)
{
        struct loongson_connector *ls_connector = to_loongson_connector(connector);
	struct i2c_adapter *adapter = ls_connector->i2c->adapter;
	struct edid *edid = NULL;
        int num_modes = 0;

	edid = drm_get_edid(connector, adapter);

	if (edid) {
		INIT_LIST_HEAD(&connector->probed_modes);
		drm_connector_update_edid_property(connector, edid);
		num_modes = drm_add_edid_modes(connector, edid);
		kfree(edid);
	} else {
		num_modes = drm_add_modes_noedid(connector, 1920, 1080);
		drm_set_preferred_mode(connector, 1024, 768);
	}

	return num_modes;
}

static enum drm_mode_status
gsgpu_dc_connector_mode_valid(struct drm_connector *connector,
			      struct drm_display_mode *mode)
{
	if (mode->hdisplay > 1920)
		return MODE_BAD;
	if (mode->vdisplay > 1080)
		return MODE_BAD;
	if (mode->clock > 340000)
		return MODE_CLOCK_HIGH;
	if (mode->hdisplay % 64)
		return MODE_BAD;
	if (mode->hdisplay == 1152)
		return MODE_BAD;

	return MODE_OK;
}

static const struct drm_connector_helper_funcs dc_connector_helper_funcs = {
	.get_modes = gsgpu_dc_connector_get_modes,
	.mode_valid = gsgpu_dc_connector_mode_valid,
	.best_encoder = best_encoder
};

void gsgpu_dc_hotplug_config(struct loongson_device *ldev)
{
	struct loongson_connector *ls_connector;
	int i;
	u32 value = ls_mm_rreg(ldev, LS_FB_INT_REG);
	u32 val_vga = ls_mm_rreg(ldev, DC_VGA_HOTPULG_CFG);

	ldev->vga_hpd_status = connector_status_disconnected;
	for (i = 0; i < ldev->num_crtc; i++)  {
		ls_connector = ldev->mode_info[i].connector;
		switch (ls_connector->id) {
		case 0:
			if (ls_connector->hotplug == irq) {
				value |= DC_INT_VGA_HOTPLUG_EN | DC_INT_HDMI0_HOTPLUG_EN;
				val_vga |= VGA_HOTPLUG_ACCESS;
			} else {
				value &= ~DC_INT_VGA_HOTPLUG_EN;
				value &= ~DC_INT_HDMI0_HOTPLUG_EN;
			}
			break;
		case 1:
			if (ls_connector->hotplug == irq)
				value |= DC_INT_HDMI1_HOTPLUG_EN;
			else
				value &= ~DC_INT_HDMI1_HOTPLUG_EN;
			break;
		}
	}

	ls_mm_wreg(ldev, LS_FB_INT_REG, value);
	ls_mm_wreg(ldev, DC_VGA_HOTPULG_CFG, val_vga);
}

static enum drm_connector_status
gsgpu_dc_connector_detect(struct drm_connector *connector, bool force)
{
	struct loongson_device *ldev = connector->dev->dev_private;
	struct loongson_connector *ls_connector = to_loongson_connector(connector);
	enum drm_connector_status status = connector_status_disconnected;
	int reg_val = ls_mm_rreg(ldev, DC_HDMI_HOTPLUG_STATUS);

	switch (connector->index) {
	case 0:
		if (reg_val & HDMI0_HOTPLUG_STATUS)
			status = connector_status_connected;

		if (ls_connector->hotplug == polling) {
			if (is_connected(ls_connector))
				ldev->vga_hpd_status = connector_status_connected;
			else
				ldev->vga_hpd_status = connector_status_disconnected;
		}

		if (status != ldev->vga_hpd_status)
			status = connector_status_connected;
		break;
	case 1:
		if (reg_val & HDMI1_HOTPLUG_STATUS)
			status = connector_status_connected;
		break;
	}

	return status;
}

static void gsgpu_dc_connector_destroy(struct drm_connector *connector)
{
	drm_connector_unregister(connector);
	drm_connector_cleanup(connector);
	kfree(connector);
}

static const struct drm_connector_funcs gsgpu_dc_connector_funcs = {
	.dpms = drm_helper_connector_dpms,
	.detect = gsgpu_dc_connector_detect,
	.fill_modes = drm_helper_probe_single_connector_modes,
	.destroy = gsgpu_dc_connector_destroy,
};

int gsgpu_dc_connector_init(struct loongson_device *ldev, int index)
{
	struct drm_connector *connector;
        struct loongson_encoder *ls_encoder = ldev->mode_info[index].encoder;
	struct loongson_connector *ls_connector;
	struct i2c_client *ddc_client;
	int ret;
	const struct i2c_board_info ddc_info = {
		.type = "ddc-dev",
		.addr = DDC_ADDR,
		.flags = I2C_CLASS_DDC,
	};

	ls_connector = kzalloc(sizeof(struct loongson_connector), GFP_KERNEL);
	if (!ls_connector)
		return 1;

	ls_connector->ldev = ldev;
	ls_connector->id = index;
	ls_connector->type = get_connector_type(ldev, index);
	ls_connector->hotplug = get_hotplug_mode(ldev, index);

	ls_connector->i2c = &ldev->i2c_bus[index];
	mutex_init(&ls_connector->hpd_lock);

        connector = &ls_connector->base;
	connector->connector_type_id = ls_connector->type;
	drm_connector_init(ldev->dev, connector, &gsgpu_dc_connector_funcs,
			   ls_connector->type);
	drm_connector_helper_add(connector, &dc_connector_helper_funcs);
	drm_connector_register(connector);

	ls_connector->base.dpms = DRM_MODE_DPMS_OFF;
	switch (ls_connector->hotplug) {
	case irq:
		connector->polled = DRM_CONNECTOR_POLL_HPD;
		break;
	case polling:
		connector->polled = DRM_CONNECTOR_POLL_CONNECT |
				    DRM_CONNECTOR_POLL_DISCONNECT;
		break;
	case disable:
	default:
		connector->polled = 0;
		break;
	}

	drm_connector_attach_encoder(connector, &ls_encoder->base);
	ldev->mode_info[index].connector = ls_connector;
	ldev->mode_info[index].bridge_phy = NULL;
	ldev->mode_info[index].mode_config_initialized = true;

	ddc_client = i2c_new_device(ls_connector->i2c->adapter, &ddc_info);
	if (IS_ERR(ddc_client)) {
		ret = PTR_ERR(ddc_client);
		i2c_del_adapter(ls_connector->i2c->adapter);
		DRM_ERROR("Failed to create standard ddc client %d\n", index);
		return ret;
	}
	ls_connector->i2c->ddc_client = ddc_client;

	return 0;
}

/* HDMI */
void hdmi_phy_pll_config(struct loongson_device *ldev, int index, int clock)
{
	int val;
	int count;
	int reg_offset = index * 0x10;

	ls_mm_wreg(ldev, HDMI_PHY_PLLCFG_REG + reg_offset, 0x0);
	ls_mm_wreg(ldev, HDMI_PHY_CTRL_REG + reg_offset, 0x0);

	if (clock >= 170000)
		val = (0x0 << 13) | (0x28 << 6) | (0x10 << 1) | (0 << 0);
	else if (clock >= 85000 && clock < 170000)
		val = (0x1 << 13) | (0x28 << 6) | (0x8 << 1) | (0 << 0);
	else if (clock >= 42500 && clock < 85000)
		val = (0x2 << 13) | (0x28 << 6) | (0x4 << 1) | (0 << 0);
	else if (clock >= 21250 && clock < 42500)
		val = (0x3 << 13) | (0x28 << 6) | (0x2 << 1) | (0 << 0);

	ls_mm_wreg(ldev, HDMI_PHY_PLLCFG_REG + reg_offset, val);
	val |= (1 << 0);
	ls_mm_wreg(ldev, HDMI_PHY_PLLCFG_REG + reg_offset, val);

	/* wait pll lock */
	while(!(ls_mm_rreg(ldev, HDMI_PHY_PLLCFG_REG + reg_offset) & 0x10000)) {
		count++;
		if (count >= 1000) {
			DRM_ERROR("GSGPU HDMI PHY PLL lock failed\n");
			return;
		}
	}

	ls_mm_wreg(ldev, HDMI_PHY_CTRL_REG + reg_offset, 0xf03);
}

int loongson_hdmi_resume(struct loongson_device *ldev)
{
	int index;
	int reg_offset;

	for (index = 0; index < 2; index++) {
		reg_offset = index * 0x10;
		ls_mm_wreg(ldev, HDMI_CTRL_REG + reg_offset, 0x287);
		ls_mm_wreg(ldev, HDMI_ZONEIDLE_REG + reg_offset, 0x00400040);
	}

	return 0;
}

int gsgpu_dc_hdmi_init(struct loongson_device *ldev)
{
	u32 val;
	u32 link = 0;
	int reg_offset;

	for (link = 0; link < 2; link++) {
		reg_offset = link * 0x10;

		/* enable hdmi */
		ls_mm_wreg(ldev, HDMI_CTRL_REG + reg_offset, 0x287);

		/* hdmi zone idle */
		ls_mm_wreg(ldev, HDMI_ZONEIDLE_REG + reg_offset, 0x00400040);

		//Audio N
		// 44.1KHz * 4, dynamic update N && CTS value
		ls_mm_wreg(ldev, HDMI_AUDIO_NCFG_REG + reg_offset, 6272);

		//Enable Send CTS
		ls_mm_wreg(ldev, HDMI_AUDIO_CTSCFG_REG + reg_offset, 0x80000000);

		//Audio AIF
		//enable AIF,set freq,and set CC = 1, CA = 0
		ls_mm_wreg(ldev, HDMI_AUDIO_INFOFRAME_REG + reg_offset, 0x11);

		//Update AIF
		val = ls_mm_rreg(ldev, HDMI_AUDIO_INFOFRAME_REG + reg_offset);
		val |= 0x4;
		ls_mm_wreg(ldev, HDMI_AUDIO_INFOFRAME_REG + reg_offset, val);

		//Audio Sample Packet
		ls_mm_wreg(ldev, HDMI_AUDIO_SAMPLE_REG + reg_offset, 0x1);
	}

	DRM_INFO("GSGPU HDMI init finish.\n");
	return 0;
}
