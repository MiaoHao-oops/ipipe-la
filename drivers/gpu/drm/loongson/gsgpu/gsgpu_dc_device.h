#ifndef __DC_CRTC_H__
#define __DC_CRTC_H__

#define PCI_DEVICE_ID_GSGPU 0x7A25
#define PCI_DEVICE_ID_GSGPU_DC 0x7a36

/* register definitions */
#define DC_FB_CFG_REG      0x1240
#define DC_FB_CFG_DMA_32 (0x3 << 16)
#define DC_FB_CFG_DMA_64 (0x2 << 16)
#define DC_FB_CFG_DMA_128 (0x1 << 16)
#define DC_FB_CFG_DMA_256 (0x0 << 16)
#define DC_FB_ADDR0_REG    0x1260
#define DC_FB_ADDR0_REG_HI 0x15A0
#define DC_FB_ADDR1_REG    0x1580
#define DC_FB_ADDR1_REG_HI 0x15C0
#define DC_FB_STRI_REG     0x1280
#define DC_FB_START_REG    0x1300
#define DC_DITHER_CFG_REG  0x1360
#define DC_DITHER_LOW_REG  0x1380
#define DC_DITHER_HIG_REG  0x13A0
#define DC_PANEL_CFG_REG   0x13C0
#define DC_PANCFG_BASE     0x80001010
#define DC_HDISPLAY_REG    0x1400
#define DC_VDISPLAY_REG    0x1480
#define DC_VSYNC_REG       0x14A0

#define DC_HDMI_HOTPLUG_STATUS 0x1ba0
#define DC_VGA_HOTPULG_CFG     0x1bb0
#define VGA_HOTPLUG_ACCESS  BIT(0)
#define VGA_HOTPLUG_EXTRACT  BIT(1)


#define DC_INT_HDMI0_HOTPLUG_EN BIT(29)
#define DC_INT_HDMI1_HOTPLUG_EN BIT(30)
#define DC_INT_VGA_HOTPLUG_EN BIT(31)
#define HDMI0_HOTPLUG_STATUS  BIT(0)
#define HDMI1_HOTPLUG_STATUS  BIT(1)

#define HDMI_INT_HOTPLUG0_CTL   BIT(13)
#define HDMI_INT_HOTPLUG1_CTL   BIT(14)
#define VGA_INT_HOTPLUG_CTL     BIT(15)

#define HDMI_ZONEIDLE_REG 	0x1700
#define HDMI_CTRL_REG		0x1720

#define HDMI_AUDIO_BUF_REG	 0x1740
#define HDMI_AUDIO_NCFG_REG	 0x1760
#define HDMI_AUDIO_CTSCFG_REG	 0x1780
#define HDMI_AUDIO_CTSCALCFG_REG 0x17a0
#define HDMI_AUDIO_INFOFRAME_REG 0x17c0
#define HDMI_AUDIO_SAMPLE_REG	 0x17e0

#define HDMI_PHY_CTRL_REG	 0x1800
#define HDMI_PHY_PLLCFG_REG	 0x1820

#define GAMMA_INDEX_REG		 0x14e0
#define GAMMA_DATA_REG 	         0x1500

int loongson_hdmi_resume(struct loongson_device *ldev);
int gsgpu_dc_hdmi_init(struct loongson_device *ldev);
void hdmi_phy_pll_config(struct loongson_device *ldev, int index, int clock);
int gsgpu_dc_connector_init(struct loongson_device *ldev, int index);
struct loongson_encoder *gsgpu_dc_encoder_init(struct loongson_device *ldev, int index);
void gsgpu_dc_hotplug_config(struct loongson_device *ldev);

#endif /* __DC_CRTC_H__ */
