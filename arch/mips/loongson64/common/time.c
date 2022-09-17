/*
 * Copyright (C) 2007 Lemote, Inc. & Institute of Computing Technology
 * Author: Fuxin Zhang, zhangfx@lemote.com
 *
 * Copyright (C) 2009 Lemote Inc.
 * Author: Wu Zhangjin, wuzhangjin@gmail.com
 *
 *  This program is free software; you can redistribute	 it and/or modify it
 *  under  the terms of	 the GNU General  Public License as published by the
 *  Free Software Foundation;  either version 2 of the	License, or (at your
 *  option) any later version.
 */
#include <asm/mc146818-time.h>
#include <asm/time.h>
#include <asm/hpet.h>

#include <loongson.h>
#include <cs5536/cs5536_mfgpt.h>
#include <loongson-pch.h>

void __init plat_time_init(void)
{
	/* setup mips r4k timer */
	mips_hpt_frequency = cpu_clock_freq / 2;

	if (cpu_guestmode)
		preset_lpj = cpu_clock_freq / HZ;

#ifdef CONFIG_LOONGSON_HPET
	if (!cpu_guestmode)
		setup_hpet_timer();
#else
	setup_mfgpt0_timer();
#endif
}

void read_persistent_clock64(struct timespec64 *ts)
{
	if (loongson_pch->type == LS7A)
		ts->tv_sec = loongson_ls7a_get_rtc_time();
	else if (loongson_pch->type == RS780E)
		ts->tv_sec = mc146818_get_cmos_time();
	ts->tv_nsec = 0;
}
