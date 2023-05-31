# SPDX-License-Identifier: GPL-2.0
ifneq ($(CONFIG_BUILTIN_DTB_NAME),"")
	dtb-y	:= $(patsubst "%",%,$(CONFIG_BUILTIN_DTB_NAME)).dtb
else
	dtb-$(CONFIG_LOONGSON_2K500) += ls2k500_hl_mb.dtb ls2k500_mini_dp.dtb ls2k500_dayu400_mb.dtb ls2k500_modi_hct.dtb
endif

obj-y		+= $(patsubst %.dtb, %.dtb.o, $(dtb-y))
