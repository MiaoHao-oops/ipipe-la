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



#ifndef __LSDC_CRTC_H__
#define __LSDC_CRTC_H__

#include <drm/drm_device.h>
#include <drm/drm_crtc.h>

struct loongson_crtc {
	struct drm_crtc base;
	unsigned int crtc_id;
	struct lsdc_pll *pix_pll;
};


#define to_loongson_crtc(x)             \
		container_of(x, struct loongson_crtc, base)


int lsdc_crtc_init(struct drm_device *ddev,
		   unsigned int index,
		   struct lsdc_pll *pixpll,
		   struct drm_plane *fb_plane,
		   struct drm_plane *cursor_plane);



#endif
