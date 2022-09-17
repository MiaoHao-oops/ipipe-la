// SPDX-License-Identifier: GPL-2.0-or-later

#include "bridge_phy.h"
#include "bridge_phy_interface.h"
#include "../loongson_drv.h"
#include "../loongson_vbios.h"

static const char legacy_encoder_timing[ENCODER_OBJECT_ID_MAX][TIMING_MAX] = {
	[ENCODER_OBJECT_ID_HDMI_IT66121] = {
		0x0F, 0x38, 0x62, 0x80, 0x64, 0x90, 0x04, 0x20, 0x04, 0x1D,
		0x61, 0x30, 0x62, 0x18, 0x64, 0x1D, 0x68, 0x10, 0x62, 0x88,
		0x64, 0x94, 0x68, 0x00, 0x61, 0x10, 0x04, 0x05, 0x05, 0xA0,
		0x65, 0x00, 0xD1, 0x08, 0x65, 0x00, 0xFF, 0xC3, 0xFF, 0xA5,
		0x20, 0x88, 0x37, 0x02, 0x20, 0x08, 0xFF, 0xFF, 0x09, 0xFF,
		0x0A, 0xFF, 0x0B, 0xFF, 0x0C, 0xFF, 0x0D, 0xFF, 0x0E, 0xFF,
		0x0f, 0x38, 0x05, 0xA0, 0x61, 0x10, 0x62, 0x80, 0x64, 0x90,
		0x61, 0x00, 0x62, 0x88, 0x64, 0x94, 0x68, 0x00, 0x61, 0x10,
		0x62, 0x10, 0x64, 0x19, 0x61, 0x00, 0x62, 0x18, 0x64, 0x1D,
		0x68, 0x00, 0x0F, 0x00, 0x61, 0x10, 0x62, 0x88, 0x64, 0x94,
		0x68, 0x00, 0x04, 0x1D, 0x04, 0x15, 0x61, 0x00, 0x0F, 0x00,
		0xC0, 0x01, 0xC1, 0x00, 0xC6, 0x03, 0xCD, 0x03, 0xCE, 0x03, },
	[ENCODER_OBJECT_ID_HDMI_LT8618] = {
		0xff, 0x80, 0xee, 0x01, 0xff, 0x80, 0x11, 0x00, 0x13, 0xf1,
		0x13, 0xf9, 0xff, 0x81, 0x02, 0x66, 0x0a, 0x06, 0x15, 0x06,
		0x4e, 0xa8, 0xff, 0x82, 0x1b, 0x77, 0x1c, 0xEC, 0xff, 0x80,
		0x0A, 0x80, 0xff, 0x82, 0x45, 0x70, 0x4f, 0x40, 0x50, 0x00,
		0x47, 0x07, 0xff, 0x81, 0x23, 0x40, 0x24, 0x64, 0x26, 0x55,
		0x29, 0x04, 0x25, 0x01, 0x2c, 0x94, 0x2d, 0x99, 0x4d, 0x00,
		0x27, 0x60, 0x28, 0x00, 0xff, 0x81, 0x2b, 0x00, 0x2e, 0x00,
		0xff, 0x82, 0xde, 0x00, 0xde, 0xc0, 0xff, 0x80, 0x16, 0xf1,
		0x18, 0xdc, 0x18, 0xfc, 0x16, 0xf3, 0xff, 0x80, 0x16, 0xe3,
		0x16, 0xf3, 0xff, 0x84, 0x43, 0x31, 0x44, 0x10, 0x45, 0x2a,
		0x47, 0x04, 0x10, 0x2c, 0x12, 0x64, 0x3d, 0x0a, 0xff, 0x80,
		0x11, 0x00, 0x13, 0xf1, 0x13, 0xf9, 0xff, 0x81, 0x30, 0xea,
		0x31, 0x44, 0x32, 0x4a, 0x33, 0x0b, 0x34, 0x00, 0x35, 0x00,
		0x36, 0x00, 0x37, 0x44, 0x3f, 0x0f, 0x40, 0xa0, 0x41, 0xa0,
		0x42, 0xa0, 0x43, 0xa0, 0x44, 0x0a, },
	[ENCODER_OBJECT_ID_EDP_NCS8805] = {},
};

static int legacy_encoder_timing_quirk(struct bridge_resource *res)
{
	int i, ret;
	char buf[2];
	struct i2c_msg msg;
	struct i2c_adapter *adapter;
	struct loongson_encoder *ls_encoder;
	int encoder_obj;
	int size = 0;

	ls_encoder = res->ls_encoder;
	adapter = ls_encoder->i2c->adapter;
	msg.addr = res->i2c_dev_addr;
	msg.flags = 0;
	msg.buf = buf;
	msg.len = ARRAY_SIZE(buf);
	encoder_obj = res->encoder_obj;

	switch (encoder_obj) {
	case ENCODER_OBJECT_ID_HDMI_IT66121:
		size = PHY_IT66121_TIMING_MAX;
		DRM_INFO("encoder timing filling 66121\n");
		break;
	case ENCODER_OBJECT_ID_HDMI_LT8618:
		size = PHY_LT8618_TIMING_MAX;
		DRM_INFO("encoder timing filling 8618\n");
		break;
	}

	for (i = 0; i < size/2; i++) {
		buf[0] = legacy_encoder_timing[encoder_obj][2 * i];
		buf[1] = legacy_encoder_timing[encoder_obj][2 * i + 1];
		ret = i2c_transfer(adapter, &msg, 1);
		if (ret != 1) {
			DRM_ERROR("Failed to send timing %#x=%#x, ret %d\n",
				  buf[0], buf[1], ret);
			return -EIO;
		}
	}

	return 0;
}

/**
 * @section Bridge-phy connector functions
 */
static int bridge_phy_connector_get_modes(struct drm_connector *connector)
{
	struct bridge_phy *phy = connector_to_bridge_phy(connector);

	if (phy->ddc_funcs->get_modes)
		return phy->ddc_funcs->get_modes(phy, connector);

	DRM_DEV_ERROR(to_dev(phy), "Missing necessary feature get_modes\n");
	return -EPERM;
}

static enum drm_mode_status
bridge_phy_connector_mode_valid(struct drm_connector *connector,
				struct drm_display_mode *mode)
{
	struct bridge_phy *phy = connector_to_bridge_phy(connector);

	if (phy->cfg_funcs->mode_valid)
		return phy->cfg_funcs->mode_valid(connector, mode);

	return MODE_OK;
}

static struct drm_encoder *
bridge_phy_connector_best_encoder(struct drm_connector *connector)
{
	int enc_id;

	enc_id = connector->encoder_ids[0];
	/* pick the encoder ids */
	if (enc_id)
		return drm_encoder_find(connector->dev, NULL, enc_id);

	DRM_ERROR("Failed to get encoder %d\n", enc_id);
	return NULL;
}

static struct drm_connector_helper_funcs bridge_phy_connector_helper_funcs = {
	.get_modes = bridge_phy_connector_get_modes,
	.mode_valid = bridge_phy_connector_mode_valid,
	.best_encoder = bridge_phy_connector_best_encoder,
};

static enum drm_connector_status
bridge_phy_connector_detect(struct drm_connector *connector, bool force)
{
	struct loongson_device *ldev = connector->dev->dev_private;
	enum drm_connector_status status;
	struct bridge_phy *phy;

	status = connector_status_unknown;
	phy = connector_to_bridge_phy(connector);
	if (phy->hpd_funcs && phy->hpd_funcs->get_hpd_status) {
		status = phy->hpd_funcs->get_hpd_status(phy) ?
				       connector_status_connected :
				       connector_status_disconnected;
	}

	DRM_DEBUG("[Bridge_phy] detected [CONNECTOR:%d:%s] %s\n",
		  connector->base.id, connector->name,
		  drm_get_connector_status_name(status));

	if (status == connector_status_connected) {
		if (connector->index == 0)
			ldev->connector_active0 = 1;
		if (connector->index == 1)
			ldev->connector_active1 = 1;
	} else {
		if (connector->index == 0)
			ldev->connector_active0 = 0;
		if (connector->index == 1)
			ldev->connector_active1 = 0;
	}

	return status;
}

static const struct drm_connector_funcs bridge_phy_connector_funcs = {
	.dpms = drm_helper_connector_dpms,
	.detect = bridge_phy_connector_detect,
	.fill_modes = drm_helper_probe_single_connector_modes,
	.destroy = drm_connector_cleanup,
	.reset = drm_atomic_helper_connector_reset,
	.atomic_duplicate_state = drm_atomic_helper_connector_duplicate_state,
	.atomic_destroy_state = drm_atomic_helper_connector_destroy_state,
};

static int legacy_connector_init(struct bridge_resource *res)
{
	int i, ret;
	struct i2c_adapter *adapter;
	struct i2c_client *ddc_client;
	struct loongson_device *ldev;
	struct loongson_encoder *ls_encoder;
	struct loongson_connector *ls_connector;

	const struct i2c_board_info ddc_info = {
		.type = "ddc-dev",
		.addr = DDC_ADDR,
		.flags = I2C_CLASS_DDC,
	};

	i = res->display_pipe_index;
	ldev = res->ldev;
	ls_encoder = res->ls_encoder;
	adapter = ls_encoder->i2c->adapter;

	ddc_client = i2c_new_device(adapter, &ddc_info);
	if (IS_ERR(ddc_client)) {
		ret = PTR_ERR(ddc_client);
		i2c_del_adapter(adapter);
		DRM_ERROR("Failed to create standard ddc client\n");
		return ret;
	}

	ls_connector = loongson_connector_init(ldev, ls_encoder->connector_id);
	if (ls_connector == NULL) {
		DRM_ERROR("Failed to initialize Legacy connector[%d]\n", i);
		return -ENODEV;
	}
	ls_connector->i2c->ddc_client = ddc_client;

	drm_connector_attach_encoder(&ls_connector->base, &ls_encoder->base);
	ldev->mode_info[i].connector = ls_connector;
	ldev->mode_info[i].bridge_phy = NULL;
	ldev->mode_info[i].mode_config_initialized = true;

	DRM_DEBUG("Legacy connector-%d init, standard ddc@0x50\n", i);
	return 0;
}

/**
 * @section Bridge-phy core functions
 */
static void bridge_phy_enable(struct drm_bridge *bridge)
{
	struct bridge_phy *phy = to_bridge_phy(bridge);

	DRM_DEBUG("[Bridge_phy] [%s] enable\n", phy->res->chip_name);
	if (phy->cfg_funcs->afe_high)
		phy->cfg_funcs->afe_high(phy);
	if (phy->cfg_funcs->afe_set_tx)
		phy->cfg_funcs->afe_set_tx(phy, TRUE);
	if (phy->cfg_funcs->hdmi_audio)
		phy->cfg_funcs->hdmi_audio(phy);
}

static void bridge_phy_disable(struct drm_bridge *bridge)
{
	struct bridge_phy *phy = to_bridge_phy(bridge);

	DRM_DEBUG("[Bridge_phy] [%s] disable\n", phy->res->chip_name);
	if (phy->cfg_funcs->afe_low)
		phy->cfg_funcs->afe_low(phy);
	if (phy->cfg_funcs->afe_set_tx)
		phy->cfg_funcs->afe_set_tx(phy, FALSE);
}

static int __bridge_phy_mode_set(struct bridge_phy *phy,
				 const struct drm_display_mode *mode,
				 const struct drm_display_mode *adj_mode)
{
	if (!phy->cfg_funcs->mode_set) {
		DRM_ERROR("Missing necessary feature mode_set\n");
		return -EPERM;
	}
	if (phy->mode_config.input_mode.gen_sync)
		DRM_DEV_DEBUG(to_dev(phy), "bridge_phy gen_sync\n");
	if (phy->hdmi_aux_funcs && phy->hdmi_aux_funcs->set_avi_infoframe)
		phy->hdmi_aux_funcs->set_avi_infoframe(phy, mode);
	if (phy->hdmi_aux_funcs && phy->hdmi_aux_funcs->set_hdcp)
		phy->hdmi_aux_funcs->set_hdcp(phy);

	if (phy->cfg_funcs->mode_set_pre)
		phy->cfg_funcs->mode_set_pre(&phy->bridge, mode, adj_mode);
	phy->cfg_funcs->mode_set(&phy->bridge, mode, adj_mode);
	if (phy->cfg_funcs->mode_set_post)
		phy->cfg_funcs->mode_set_post(&phy->bridge, mode, adj_mode);

	return 0;
}

static void bridge_phy_mode_set(struct drm_bridge *bridge,
				struct drm_display_mode *mode,
				struct drm_display_mode *adj_mode)
{
	struct bridge_phy *phy = to_bridge_phy(bridge);

	DRM_DEBUG("[Bridge_phy] [%s] mode set\n", phy->res->chip_name);
	drm_mode_debug_printmodeline(mode);

	__bridge_phy_mode_set(phy, mode, adj_mode);
}

static int bridge_phy_attach(struct drm_bridge *bridge)
{
	struct bridge_phy *phy = to_bridge_phy(bridge);
	int ret;

	DRM_DEBUG("[Bridge_phy] %s attach\n", phy->res->chip_name);
	if (!bridge->encoder) {
		DRM_ERROR("Parent encoder object not found\n");
		return -ENODEV;
	}

	if (phy->irq)
		phy->connector.polled = DRM_CONNECTOR_POLL_HPD;
	else
		phy->connector.polled = DRM_CONNECTOR_POLL_CONNECT |
					DRM_CONNECTOR_POLL_DISCONNECT;
	DRM_DEBUG("[Bridge_phy] Set connnector poll=%d\n",
		  phy->connector.polled);

	ret = drm_connector_init(bridge->dev, &phy->connector,
				 &bridge_phy_connector_funcs,
				 phy->connector_type);
	if (ret) {
		DRM_ERROR("[Bridge_phy] %s Failed to initialize connector\n",
			  phy->res->chip_name);
		return ret;
	}

	drm_connector_helper_add(&phy->connector,
				 &bridge_phy_connector_helper_funcs);
	drm_connector_attach_encoder(&phy->connector, bridge->encoder);

	return ret;
}

static const struct drm_bridge_funcs bridge_funcs = {
	.enable = bridge_phy_enable,
	.disable = bridge_phy_disable,
	.mode_set = bridge_phy_mode_set,
	.attach = bridge_phy_attach,
};

static int bridge_phy_bind(struct bridge_phy *phy)
{
	int ret;

	phy->bridge.funcs = &bridge_funcs;
	drm_bridge_add(&phy->bridge);
	ret = drm_bridge_attach(phy->encoder, &phy->bridge, NULL);
	if (ret) {
		DRM_ERROR("[Bridge_phy] %s Failed to attach phy ret %d\n",
			  phy->res->chip_name, ret);
		return ret;
	}

	DRM_INFO("[Bridge_phy] %s attach to encoder%d, type %d\n",
		 phy->res->chip_name, phy->encoder->index,
		 phy->encoder->encoder_type);

	return 0;
}

/**
 * @section Bridge-phy helper functions
 */
void bridge_phy_reg_mask_seq(struct bridge_phy *phy,
			     const struct reg_mask_seq *seq, size_t seq_size)
{
	unsigned int i;
	struct regmap *regmap;

	regmap = phy->phy_regmap;
	for (i = 0; i < seq_size; i++)
		regmap_update_bits(regmap, seq[i].reg, seq[i].mask, seq[i].val);
}

int bridge_phy_reg_dump(struct bridge_phy *phy, size_t start, size_t count)
{
	u8 *buf;
	int ret;
	unsigned int i;

	buf = kzalloc(count, GFP_KERNEL);
	if (IS_ERR(buf)) {
		ret = PTR_ERR(buf);
		return -ENOMEM;
	}
	ret = regmap_raw_read(phy->phy_regmap, start, buf, count);
	for (i = 0; i < count; i++)
		pr_info("[%lx]=%02x", start + i, buf[i]);

	kfree(buf);
	return ret;
}

static char *get_encoder_chip_name(int encoder_obj)
{
	switch (encoder_obj) {
	case ENCODER_OBJECT_ID_HDMI_IT66121:
		return "it66121";
	case ENCODER_OBJECT_ID_HDMI_SIL9022:
		return "sil902x";
	case ENCODER_OBJECT_ID_HDMI_LT8618:
		return "lt8618";
	case ENCODER_OBJECT_ID_HDMI_MS7210:
		return "ms7210";
	case ENCODER_OBJECT_ID_EDP_NCS8805:
		return "ncs8805";
	default:
		DRM_WARN("No matching encoder chip 0x%x, using default\n",
			 encoder_obj);
		return "unknown";
	}
}

static int get_bridge_connector_type(struct bridge_phy *phy)
{
	switch (phy->res->encoder_obj) {
	case 0:
		return DRM_MODE_CONNECTOR_Unknown;
	case 1:
	case 0x10 ... 0x1F:
		return DRM_MODE_CONNECTOR_VGA;
	case 2:
	case 0x30 ... 0x3F:
		return DRM_MODE_CONNECTOR_HDMIA;
	default:
		DRM_ERROR("Unknown connector type %d\n", phy->res->encoder_obj);
		return DRM_MODE_CONNECTOR_Unknown;
	}
}

static int bridge_phy_get_resources_from_vbios(struct bridge_resource *res)
{
	struct loongson_device *ldev;
	int encoder_id;
	int encoder_obj;
	const char *chip_name;
	unsigned int i2c_bus_num;
	unsigned short i2c_dev_addr;
	unsigned int irq_gpio;
	unsigned int gpio_placement;

	ldev = res->ldev;
	encoder_id = res->ls_encoder->encoder_id;
	encoder_obj = get_encoder_chip(ldev, encoder_id);
	chip_name = get_encoder_chip_name(encoder_obj);
	i2c_dev_addr = get_encoder_chip_addr(ldev, encoder_id);
	i2c_bus_num = res->ls_encoder->i2c_id;
	irq_gpio = get_connector_irq_gpio(ldev, encoder_id);
	gpio_placement = get_connector_gpio_placement(ldev, encoder_id);
	if (gpio_placement < 0) {
		DRM_ERROR("Failed to parse bridge resource\n");
		return -EINVAL;
	}

	res->encoder_obj = encoder_obj;
	snprintf(res->chip_name, NAME_SIZE_MAX, "%s", chip_name);
	res->i2c_bus_num = i2c_bus_num;
	res->i2c_dev_addr = i2c_dev_addr;
	res->irq_gpio = irq_gpio;
	res->gpio_placement = gpio_placement;

	DRM_INFO("Parse resource:Encoder [0x%02x-%s]:i2c%d-0x%02x irq(%d,%d)\n",
		 res->encoder_obj, res->chip_name, res->i2c_bus_num,
		 res->i2c_dev_addr, res->gpio_placement, res->irq_gpio);

	return 0;
}

static int bridge_phy_encoder_obj_select(struct bridge_resource *res)
{
	switch (res->encoder_obj) {
	case ENCODER_OBJECT_ID_HDMI_IT66121:
		bridge_phy_it66121_init(res);
		break;
	case ENCODER_OBJECT_ID_HDMI_LT8618:
		bridge_phy_lt8618_init(res);
		break;
	case ENCODER_OBJECT_ID_HDMI_MS7210:
		bridge_phy_ms7210_init(res);
		break;
	default:
		DRM_ERROR("No matching chip can be selected!\n");
		break;
	}

	return 0;
}

static int bridge_phy_get_resources(struct bridge_phy *phy,
				    struct bridge_resource *res)
{
	int index;

	index = res->display_pipe_index;
	phy->encoder = &res->ls_encoder->base;
	phy->ldev = res->ldev;
	phy->li2c = &res->ldev->i2c_bus[index];
	phy->display_pipe_index = index;
	phy->bridge.driver_private = phy;
	phy->res = res;
	phy->connector_type = get_bridge_connector_type(phy);

	DRM_DEBUG("Pipe[%d]:Encoder PHY [0x%02x-%s]: i2c%d-0x%02x irq(%d,%d)\n",
		  index, res->encoder_obj, res->chip_name, res->i2c_bus_num,
		  res->i2c_dev_addr, res->gpio_placement, res->irq_gpio);

	return 0;
}

static inline bool bridge_phy_check_feature(const struct bridge_phy *phy,
					    u32 feature)
{
	return phy->feature & feature;
}

static int bridge_phy_add_hpd_funcs(struct bridge_phy *phy, void *funcs)
{
	phy->hpd_funcs = (struct bridge_phy_hpd_funcs *)funcs;

	return 0;
}

static int bridge_phy_add_ddc_funcs(struct bridge_phy *phy, void *funcs)
{
	phy->ddc_funcs = (struct bridge_phy_ddc_funcs *)funcs;

	return 0;
}

static int bridge_phy_add_hdmi_aux_funcs(struct bridge_phy *phy, void *funcs)
{
	phy->hdmi_aux_funcs = (struct bridge_phy_hdmi_aux_funcs *)funcs;

	return 0;
}

static int bridge_phy_add_helper_funcs(struct bridge_phy *phy,
				       struct bridge_phy_helper *helper)
{
	u32 feature, check_feature;

	feature = phy->feature;
	phy->helper = helper;

	DRM_INFO("[Bridge_phy] %s features=%#x, add helper funcs\n",
		 phy->res->chip_name, feature);
	check_feature = SUPPORT_HPD;
	if (!bridge_phy_check_feature(phy, check_feature))
		goto feature_error;
	bridge_phy_add_hpd_funcs(phy, helper->hpd_funcs);

	check_feature = SUPPORT_DDC;
	if (!bridge_phy_check_feature(phy, check_feature))
		goto feature_error;
	bridge_phy_add_ddc_funcs(phy, helper->ddc_funcs);

	check_feature = SUPPORT_HDMI_AUX;
	if (!bridge_phy_check_feature(phy, check_feature))
		goto feature_error;
	bridge_phy_add_hdmi_aux_funcs(phy, helper->hdmi_aux_funcs);

	return 0;

feature_error:
	DRM_ERROR("[Bridge_phy] %s Missing necessary feature %d\n",
		  phy->res->chip_name, check_feature);
	return -EPERM;
}

static int bridge_phy_register_i2c_device(struct bridge_phy *phy)
{
	int ret;
	struct i2c_adapter *i2c_adap;
	struct i2c_client *i2c_client;
	struct bridge_resource *res;
	struct i2c_board_info board_info;

	res = phy->res;
	i2c_adap = phy->li2c->adapter;
	if (IS_ERR(i2c_adap)) {
		ret = PTR_ERR(i2c_adap);
		DRM_ERROR("Failed to get i2c adapter %d\n", res->i2c_bus_num);
		return ret;
	}

	memset(&board_info, 0, sizeof(struct i2c_board_info));
	strncpy(board_info.type, res->chip_name, I2C_NAME_SIZE);
	board_info.dev_name = res->chip_name;
	board_info.addr = res->i2c_dev_addr;
	DRM_INFO("Add encoder PHY: %s@i2c%d-0x%02x\n", board_info.type,
		 i2c_adap->nr, board_info.addr);
	i2c_client = i2c_new_device(i2c_adap, &board_info);
	if (IS_ERR(i2c_client)) {
		ret = PTR_ERR(i2c_client);
		DRM_ERROR("Failed to create i2c-dev %s\n", res->chip_name);
		return ret;
	}

	i2c_set_clientdata(i2c_client, phy);
	phy->i2c_phy = i2c_client;
	i2c_put_adapter(i2c_adap);

	DRM_DEBUG("Create %s i2c-dev [%d-0x%0xx]\n", res->chip_name,
		  res->i2c_bus_num, res->i2c_dev_addr);
	return 0;
}

static int bridge_phy_regmap_init(struct bridge_phy *phy)
{
	int ret;
	struct regmap *regmap;

	mutex_init(&phy->ddc_status.ddc_bus_mutex);
	atomic_set(&phy->irq_status, 0);

	regmap = devm_regmap_init_i2c(phy->i2c_phy, phy->helper->regmap_cfg);
	if (IS_ERR(regmap)) {
		ret = PTR_ERR(regmap);
		return -ret;
	}
	phy->phy_regmap = regmap;

	return 0;
}

static int bridge_phy_register_irq(struct bridge_phy *phy)
{
	int ret;
	char irq_name[NAME_SIZE_MAX];
	struct bridge_resource *res;

	res = phy->res;
	if (res->gpio_placement)
		res->irq_gpio += LS7A_GPIO_OFFSET;

	ret = gpio_is_valid(res->irq_gpio);
	if (!ret)
		goto error_gpio_valid;
	sprintf(irq_name, "%s-irq", res->chip_name);

	ret = gpio_request(res->irq_gpio, irq_name);
	if (ret)
		goto error_gpio_req;
	ret = gpio_direction_input(res->irq_gpio);
	if (ret)
		goto error_gpio_cfg;

	phy->irq = gpio_to_irq(res->irq_gpio);
	if (phy->irq < 0) {
		DRM_ERROR("GPIO %d has no interrupt\n", res->irq_gpio);
		phy->irq = 0;
		return -EINVAL;
	}

	ret = devm_request_threaded_irq(
		to_dev(phy), phy->irq, phy->hpd_funcs->irq_handler,
		phy->hpd_funcs->isr_thread,
		IRQF_ONESHOT | IRQF_SHARED | IRQF_TRIGGER_HIGH, res->chip_name,
		phy);
	if (ret)
		goto error_irq;

	DRM_DEV_DEBUG(to_dev(phy), "%s register irq %d\n", res->chip_name,
		      phy->irq);

	return 0;

error_irq:
	DRM_ERROR("Failed to request irq %d %d\n", phy->irq, ret);
error_gpio_cfg:
	DRM_ERROR("Failed to config gpio %d free it, %d\n", res->irq_gpio, ret);
	gpio_free(res->irq_gpio);
error_gpio_req:
	DRM_ERROR("Failed to request gpio %d, %d\n", res->irq_gpio, ret);
error_gpio_valid:
	DRM_ERROR("Invalid gpio %d, %d\n", res->irq_gpio, ret);
	return -ENODEV;
}

static int bridge_phy_hw_reset(struct bridge_phy *phy)
{
	if (phy->cfg_funcs->hw_reset)
		phy->cfg_funcs->hw_reset(phy);

	return 0;
}

static int bridge_phy_hw_init(struct bridge_phy *phy)
{
	bridge_phy_register_i2c_device(phy);
	bridge_phy_regmap_init(phy);
	bridge_phy_register_irq(phy);
	bridge_phy_hw_reset(phy);

	DRM_INFO("[Bridge_phy] %s HW init completed\n", phy->res->chip_name);

	return 0;
}

static int bridge_phy_misc_init(struct bridge_phy *phy)
{
	if (phy->helper->misc_funcs->debugfs_init)
		phy->helper->misc_funcs->debugfs_init(phy);

	return 0;
}

static int bridge_phy_chip_id_verify(struct bridge_phy *phy)
{
	int ret;
	char str[NAME_SIZE_MAX] = "";

	if (phy->helper->misc_funcs->chip_id_verify) {
		ret = phy->helper->misc_funcs->chip_id_verify(phy, str);
		if (!ret)
			DRM_ERROR("Failed to verify chip %s, return [%s]\n",
				  phy->res->chip_name, str);
		strncpy(phy->res->vendor_str, str, NAME_SIZE_MAX - 1);
		return ret;
	}

	return -ENODEV;
}

static int bridge_phy_sw_reset(struct bridge_phy *phy)
{
	if (phy->cfg_funcs->sw_enable)
		phy->cfg_funcs->sw_enable(phy);

	bridge_phy_chip_id_verify(phy);
	if (phy->cfg_funcs->sw_reset)
		phy->cfg_funcs->sw_reset(phy);
	if (phy->cfg_funcs->reg_init)
		phy->cfg_funcs->reg_init(phy);

	return 0;
}

static int bridge_phy_video_config(struct bridge_phy *phy)
{
	if (phy->cfg_funcs->video_input_cfg)
		phy->cfg_funcs->video_input_cfg(phy);
	if (phy->cfg_funcs->video_output_cfg)
		phy->cfg_funcs->video_output_cfg(phy);

	return 0;
}

static int bridge_phy_hdmi_config(struct bridge_phy *phy)
{
	enum hdmi_mode mode;

	mode = phy->mode_config.output_mode.hdmi_output_mode;
	if (phy->cfg_funcs->hdmi_output_mode)
		phy->cfg_funcs->hdmi_output_mode(phy, mode);
	if (phy->cfg_funcs->hdmi_audio)
		phy->cfg_funcs->hdmi_audio(phy);
	if (phy->cfg_funcs->hdmi_csc)
		phy->cfg_funcs->hdmi_csc(phy);
	if (phy->cfg_funcs->hdmi_hdcp_init)
		phy->cfg_funcs->hdmi_hdcp_init(phy);

	return 0;
}

static int bridge_phy_video_output_timing(struct bridge_phy *phy)
{
	if (phy->cfg_funcs->video_output_timing &&
	    phy->mode_config.input_mode.mode)
		phy->cfg_funcs->video_output_timing(
			phy, phy->mode_config.input_mode.mode);

	return 0;
}

static int bridge_phy_afe_high(struct bridge_phy *phy)
{
	if (phy->cfg_funcs->afe_high)
		phy->cfg_funcs->afe_high(phy);

	return 0;
}

static int bridge_phy_afe_set_tx(struct bridge_phy *phy, bool enable)
{
	if (phy->cfg_funcs->afe_set_tx)
		phy->cfg_funcs->afe_set_tx(phy, enable);

	return 0;
}

static int bridge_phy_default_mode_set(struct bridge_phy *phy)
{
	const struct drm_display_mode *default_mode;
	struct bridge_phy_mode_config *mode_config;

	mode_config = &phy->mode_config;
	default_mode = mode_config->input_mode.mode;

	DRM_INFO("[Bridge_phy] %s Set default mode", phy->res->chip_name);
	drm_mode_debug_printmodeline(default_mode);
	bridge_phy_video_output_timing(phy);
	bridge_phy_afe_high(phy);
	bridge_phy_afe_set_tx(phy, TRUE);

	return 0;
}

static int bridge_phy_sw_init(struct bridge_phy *phy)
{
	bridge_phy_sw_reset(phy);
	bridge_phy_video_config(phy);
	bridge_phy_hdmi_config(phy);

	DRM_INFO("[Bridge_phy] %s SW init completed\n", phy->res->chip_name);

	return 0;
}

static const struct drm_display_mode *
bridge_phy_create_mode(struct bridge_phy *phy, int hdisplay, int vdisplay)
{
	size_t i, count;
	const struct drm_display_mode *mode;
	const struct drm_display_mode *cea_mode;

	if (hdisplay < 0)
		hdisplay = 0;
	if (vdisplay < 0)
		vdisplay = 0;

	cea_mode = NULL;
	count = ARRAY_SIZE(cea_modes);
	for (i = 0; i < count; i++) {
		cea_mode = &cea_modes[i];
		if (cea_mode->hdisplay == hdisplay &&
		    cea_mode->vdisplay == vdisplay &&
		    (drm_mode_vrefresh(cea_mode) < 61) &&
		    !(cea_mode->flags & DRM_MODE_FLAG_INTERLACE))
			break;
	}

	if (cea_mode) {
		mode = drm_mode_duplicate(phy->bridge.dev, cea_mode);
		DRM_INFO("[Bridge_phy] %s Created default mode\n",
			 phy->res->chip_name);
		drm_mode_debug_printmodeline(mode);
		return mode;
	}

	DRM_WARN("Failed to match cea_mode [%dX%d]\n", hdisplay, vdisplay);
	return &cea_modes[MODE_1080P];
}

static int bridge_phy_init(struct bridge_phy *phy)
{
	const struct drm_display_mode *default_mode;
	struct bridge_phy_mode_config *mode_config;

	mode_config = &phy->mode_config;

	bridge_phy_hw_init(phy);
	bridge_phy_misc_init(phy);
	bridge_phy_bind(phy);

	default_mode = bridge_phy_create_mode(phy, 1920, 1080);
	mode_config->input_mode.mode = (struct drm_display_mode *)default_mode;
	bridge_phy_default_mode_set(phy);
	bridge_phy_sw_init(phy);

	DRM_INFO("bridge phy init finish!\n");

	return 0;
}

/**
 * @section Bridge-phy interface
 */
int loongson_bridge_bind(struct loongson_device *ldev, int index)
{
	int ret;
	struct bridge_resource *res;
	struct loongson_encoder *lencoder;

	res = kzalloc(sizeof(struct bridge_resource), GFP_KERNEL);
	if (IS_ERR(res)) {
		ret = PTR_ERR(res);
		return ret;
	}

	res->ldev = ldev;
	lencoder = ldev->mode_info[index].encoder;
	res->ls_encoder = lencoder;
	res->display_pipe_index = index;

	bridge_phy_get_resources_from_vbios(res);

	if (lencoder->config_type == encoder_kernel_driver) {
		ret = bridge_phy_encoder_obj_select(res);
		if (ret)
			return ret;
	} else {
		legacy_connector_init(res);
		if (lencoder->config_type == encoder_timing_filling)
			legacy_encoder_timing_quirk(res);
	}

	return 0;
}

struct bridge_phy *bridge_phy_alloc(struct bridge_resource *res)
{
	struct bridge_phy *bridge_phy;
	int index;

	index = res->display_pipe_index;
	bridge_phy = kzalloc(sizeof(struct bridge_phy), GFP_KERNEL);
	if (IS_ERR(bridge_phy)) {
		DRM_ERROR("Failed to alloc bridge_phy\n");
		return NULL;
	}

	bridge_phy_get_resources(bridge_phy, res);
	res->ldev->mode_info[index].bridge_phy = bridge_phy;

	return bridge_phy;
}

int bridge_phy_register(struct bridge_phy *phy,
			const struct bridge_phy_cfg_funcs *cfg_funcs,
			u32 feature, struct bridge_phy_helper *helper)
{
	phy->feature = feature;
	phy->cfg_funcs = cfg_funcs;

	bridge_phy_add_helper_funcs(phy, helper);
	bridge_phy_init(phy);

	return 0;
}

void loongson_bridge_resume(struct loongson_device *ldev)
{
	struct bridge_phy *phy;
	int i;

	for (i = 0; i < 2; i++) {
		phy = ldev->mode_info[i].bridge_phy;
		if (phy) {
			bridge_phy_sw_reset(phy);
			bridge_phy_video_config(phy);
			bridge_phy_hdmi_config(phy);
		}
	}
}
