/* SPDX-License-Identifier: GPL-2.0+ */
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

#ifndef __LSDC_REGS_H__
#define __LSDC_REGS_H__

#include "lsdc_drv.h"


/*
 * PLL
 */

#define LSDC_PLL_REF_CLK                100000           /* kHz */
#define PCLK_PRECISION_INDICATOR        10000


/*
 * Those PLL registers is not in dc's bar space,
 * there are relative to LSXX1000_CFG_REG_BASE.
 */

/* LS2K1000 */
#define LS2K1000_DC_PLL_REG             0x04A0

#define LS2K1000_PIX_PLL0_REG           0x04B0
#define LS2K1000_PIX_PLL1_REG           0x04C0

#define LS2K1000_CFG_REG_BASE           0x1fe10000

/* LS7A1000 */
#define LS7A1000_DC_PLL_REG             0x0490

#define LS7A1000_PIX_PLL0_REG           0x04B0
#define LS7A1000_PIX_PLL1_REG           0x04C0

#define LS7A1000_CFG_REG_BASE           0x10010000

/* LS2K0500 */
#define LS2K0500_PIX_PLL0_REG           0x0418
#define LS2K0500_PIX_PLL1_REG           0x0420

#define LS2K0500_CFG_REG_BASE           0x1fe10000


/*
 *  CRTC CFG
 */
#define CFG_FB_FMT                      GENMASK(2, 0)
#define CFG_FB_SWITCH                   BIT(7)
#define CFG_OUTPUT_ENABLE               BIT(8)
#define CFG_PANEL_SWITCH                BIT(9)
#define CFG_FB_IDX_FLAG                 BIT(11)
#define CFG_GAMMAR_EN_BIT               BIT(12)
#define CFG_RESET_BIT                   BIT(20)


#define CFG_EN_HSYNC                    BIT(30)
#define CFG_INV_HSYNC                   BIT(31)

#define CFG_EN_VSYNC                    BIT(30)
#define CFG_INV_VSYNC                   BIT(31)


/******** CRTC0 & DVO0 ********/

#define LSDC_CRTC0_CFG_REG              0x1240

#define LSDC_FB_ADDR0_DVO_REG           0x1260
#define LSDC_FB_ADDR1_DVO_REG           0x1580
#define LSDC_CRTC0_ADDR_HI_REG          0x15A0

#define LSDC_CRTC0_FB_ORIGIN_REG        0x1300

#define LSDC_CRTC0_STRIDE_REG           0x1280

#define LSDC_CRTC0_GAMMA_INDEX_REG      0x14e0
#define LSDC_CRTC0_GAMMA_DATA_REG       0x1500

#define FB_DITCFG_DVO0_REG              0x1360
#define FB_DITTAB_LO_DVO0_REG           0x1380
#define FB_DITTAB_HI_DVO0_REG           0x13a0

#define FB_PANCFG_DVO0_REG              0x13c0
#define FB_PANTIM_DVO0_REG              0x13e0

#define FB_HDISPLAY_DVO0_REG            0x1400
#define FB_HSYNC_DVO0_REG               0x1420
#define FB_VDISPLAY_DVO0_REG            0x1480
#define FB_VSYNC_DVO0_REG               0x14a0

#define FB_GAMINDEX_DVO0_REG            0x14E0
#define FB_GAMDATA_DVO0_REG             0x1500


/******** CTRC1 & DVO1(VGA) ********/

#define LSDC_CRTC1_CFG_REG              0x1250

#define LSDC_FB_ADDR0_DVO1_REG          0x1270
#define LSDC_FB_ADDR1_DVO1_REG          0x1590
#define LSDC_CRTC1_ADDR_HI_REG          0x15C0

#define LSDC_CRTC1_FB_ORIGIN_REG        0x1310
#define LSDC_CRTC1_STRIDE_REG           0x1290

#define LSDC_CRTC1_GAMMA_INDEX_REG      0x14F0
#define LSDC_CRTC1_GAMMA_DATA_REG       0x1510

#define FB_DITCFG_DVO1_REG              0x1370
#define FB_DITTAB_LO_DVO1_REG           0x1390
#define FB_DITTAB_HI_DVO1_REG           0x13b0

#define FB_PANCFG_DVO1_REG              0x13d0
#define FB_PANTIM_DVO1_REG              0x13f0

#define FB_HDISPLAY_DVO1_REG            0x1410
#define FB_HSYNC_DVO1_REG               0x1430
#define FB_VDISPLAY_DVO1_REG            0x1490
#define FB_VSYNC_DVO1_REG               0x14b0

#define FB_GAMINDEX_DVO1_REG            0x14f0
#define FB_GAMDATA_DVO1_REG             0x1510



/* hardware cusor related */

#define LSDC_CURSOR_CFG_REG             0x1520

#define CURSOR_ENABLE_MASK              GENMASK(1, 0)
#define CURSOR_FORMAT_DISABLE           0
#define CURSOR_FORMAT_MONOCHROME        BIT(0)
#define CURSOR_FORMAT_ARGB8888          BIT(1)
#define CURSOR_LOCATION_BIT             BIT(4)

#define LSDC_CURSOR_ADDR_REG            0x1530
#define LSDC_CURSOR_POSITION_REG        0x1540
#define LSDC_CURSOR_BG_COLOR_REG        0x1550  /* background color*/
#define LSDC_CURSOR_FG_COLOR_REG        0x1560  /* foreground color*/

#define CUR_WIDTH_SIZE                  32
#define CUR_HEIGHT_SIZE                 32


/*
 * DC Interrupt Control Register, 32bit, Address Offset: 1570
 *
 * Bits  0:10 inidicate the interrupt type, read only
 * Bits 16:26 control if the specific interrupt corresponding to bit 0~10
 * is enabled or not. Write 1 to enable, write 0 to disable
 *
 * RF: Read Finished
 * IDBU : Internal Data Buffer Underflow
 * IDBFU : Internal Data Buffer Fatal Underflow
 *
 * +----+----+----+----+----+--------+--------+--------+
 * | 31 | 30 | 29 | 28 | 27 |   26   |   25   |   24   |
 * +----+----+----+----+----+--------+--------+--------+
 * |          N/A           | Interrupt Enable Control |
 * +------------------------+--------------------------+
 *
 * +----+----+----+----+----+----+----+----+
 * | 23 | 22 | 21 | 20 | 19 | 18 | 17 | 16 |
 * +----+----+----+----+----+----+----+----+
 * |    Interrupt Enable Control Bits      |
 * +---------------------------------------+
 *
 * +----+----+----+----+------+-----------+-----------+----------+
 * | 15 | 14 | 13 | 12 |  11  |     10    |     9     |     8    |
 * +----+----+----+----+------+-----------+-----------+----------+
 * |           N/A            | FB0 IDBFU | FB1 IDBFU | FB0 IDBU |
 * +--------------------------+-----------+-----------+----------+
 *
 * +----------+--------+--------+-----------+
 * |     7    |  6     |   5    |     4     |
 * +----------+--------+--------+-----------+
 * | FB1 IDBU | FB0 RF | FB1 RF | Cursor RF |
 * +----------+--------+--------+-----------+
 *
 * +------------+------------+------------+------------+
 * |      3     |     2      |     1      |     0      |
 * +------------+------------+------------+------------+
 * | DVO0 HSYNC | DVO0 VSYNC | DVO1 HSYNC | DVO1 VSYNC |
 * +------------+------------+------------+------------+
 *
 */

#define LSDC_INT_REG                           0x1570

#define INT_CRTC0_VS                           BIT(2)
#define INT_CRTC0_HS                           BIT(3)
#define INT_CRTC0_RF                           BIT(6)
#define INT_CRTC0_IDBU                         BIT(8)
#define INT_CRTC0_IDBFU                        BIT(10)

#define INT_CURSOR_RF                          BIT(4)

#define INT_CRTC1_VS                           BIT(0)
#define INT_CRTC1_HS                           BIT(1)
#define INT_CRTC1_RF                           BIT(5)
#define INT_CRTC1_IDBU                         BIT(7)
#define INT_CRTC1_IDBFU                        BIT(9)


#define INT_CRTC0_VS_EN                        BIT(2 + 16)
#define INT_CRTC0_HS_EN                        BIT(3 + 16)
#define INT_CRTC0_RF_EN                        BIT(6 + 16)
#define INT_CRTC0_IDBU_EN                      BIT(8 + 16)
#define INT_CRTC0_IDBFU_EN                     BIT(10 + 16)

#define INT_CURSOR_RF_EN                       BIT(4 + 16)

#define INT_CRTC1_VS_EN                        BIT(0 + 16)
#define INT_CRTC1_HS_EN                        BIT(1 + 16)
#define INT_CRTC1_RF_EN                        BIT(5 + 16)
#define INT_CRTC1_IDBU_EN                      BIT(7 + 16)
#define INT_CRTC1_IDBFU_EN                     BIT(9 + 16)


#define INT_STATUS_MASK                        0x07ff


/*
 * GPIO emulated I2C, LS7A1000 Only
 *
 * DVO : Digital Video Output
 * There are two GPIO emulated i2c in LS7A1000 for reading edid from
 * the monitor, those registers are in the DC control register space.
 *
 * GPIO data register
 *  Address offset: 0x1650
 *   +---------------+-----------+-----------+
 *   | 7 | 6 | 5 | 4 |  3  |  2  |  1  |  0  |
 *   +---------------+-----------+-----------+
 *   |               |    DVO1   |    DVO0   |
 *   +      N/A      +-----------+-----------+
 *   |               | SCL | SDA | SCL | SDA |
 *   +---------------+-----------+-----------+
 */
#define LS7A_DC_GPIO_DAT_REG                   0x1650

/*
 *  GPIO Input/Output direction control register
 *  Address offset: 0x1660
 *  write 1 for Input, 0 for Output.
 */
#define LS7A_DC_GPIO_DIR_REG                   0x1660


static inline u32 lsdc_reg_read32(struct loongson_drm_device * const ldev,
				  u32 offset)
{
	u32 val;
	unsigned long flags;

	spin_lock_irqsave(&ldev->reglock, flags);
	val = readl(ldev->reg_base + offset);
	spin_unlock_irqrestore(&ldev->reglock, flags);

	return val;
}


static inline void lsdc_reg_write32(struct loongson_drm_device * const ldev,
				    u32 offset, u32 val)
{
	unsigned long flags;

	spin_lock_irqsave(&ldev->reglock, flags);
	writel(val, ldev->reg_base + offset);
	spin_unlock_irqrestore(&ldev->reglock, flags);
}

/*
 *  7A2000  HDMI Encoder
 */
#define HDMI_EN                 BIT(0)
#define HDMI_PACKET_EN          BIT(1)

#define HDMI0_ZONE_REG          0x1700
#define HDMI1_ZONE_REG          0x1710

#define HDMI0_CTRL_REG          0x1720
#define HDMI1_CTRL_REG          0x1730

#endif
