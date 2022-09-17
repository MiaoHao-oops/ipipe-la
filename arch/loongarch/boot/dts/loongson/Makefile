# SPDX-License-Identifier: GPL-2.0
ifneq ($(CONFIG_BUILTIN_DTB_NAME),"")
	dtb-y	:= $(patsubst "%",%,$(CONFIG_BUILTIN_DTB_NAME)).dtb
endif

obj-y		+= $(patsubst %.dtb, %.dtb.o, $(dtb-y))
