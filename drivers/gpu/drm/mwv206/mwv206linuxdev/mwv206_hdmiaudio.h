/*
 * JM7200 GPU driver
 *
 * Copyright (c) 2018 ChangSha JingJiaMicro Electronics Co., Ltd.
 *
 * Author:
 *      rfshen <jjwgpu@jingjiamicro.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */
#ifndef _MWV206_HDMIAUDIO_H_
#define _MWV206_HDMIAUDIO_H_

#include <sound/pcm.h>
#include <linux/kfifo.h>
#include <linux/time.h>
#include <linux/ktime.h>

#define MAC206LXDEV029 (64*1024)
#define MAC206LXDEV030 (32*1024)

#define MAC206LXDEV010    (4 * 1024)
#define MAC206LXDEV028    64
#define MAC206LXDEV027    1024

#define MAC206LXDEV026     16
#define MAC206LXDEV025     (MAC206LXDEV010 / MAC206LXDEV028)

struct V206HDMIAUDIO012 {
	uint16_t *buf;
	long bufsize;
	long rp;
	long wp;
};

struct V206DEV139 {
	spinlock_t lock;
	void __iomem *regs;
	u32 flags;
#define V206HDMIAUDIO001 0x00000001
#define V206HDMIAUDIO002 0x00000002

	struct snd_card *card;
	struct snd_pcm *pcm;
	struct snd_pcm_substream *V206HDMIAUDIO003;


	unsigned V206HDMIAUDIO006;

	struct V206HDMIAUDIO012 V206HDMIAUDIO012;

	struct platform_device *op;
	unsigned int irq;
	V206DEV025 *pdata;
	struct snd_pcm_runtime runtime;

	struct hrtimer        timer;
	struct kfifo fifo;

	int V206HDMIAUDIO027;




	ktime_t hrtime;

	char kbuf[MAC206LXDEV010 << 2];
};

int mwv206_major_get(void);
struct class *mwv206_class_get(void);


#endif