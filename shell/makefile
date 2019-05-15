
ifdef app_platform
  _APP_PLATFORM := $(app_platform)
else
  _APP_PLATFORM := android-21
endif

ifdef toolchains
  _TOOLCHAINS := $(toolchains)
else
  _TOOLCHAINS := arm-linux-androideabi
endif

ifdef toolchains_ver
  _TOOLCHAINS_VER := $(toolchains_ver)
else
  _TOOLCHAINS_VER := 4.9
endif

ifdef arch
  _ARCH := $(arch)
else
  _ARCH := arm
endif

ifndef ndk_root
  $(error "not defined ndk_root")
endif

_NDK_ROOT := $(ndk_root)
_WORK := $(shell cd)/$(lastword)

ifeq ("", "$(wildcard $(_NDK_ROOT)/sysroot)")
  SYS_INCLUDE := $(_NDK_ROOT)/platforms/$(_APP_PLATFORM)/arch-$(_ARCH)/usr/include
else
  SYS_INCLUDE := $(_NDK_ROOT)/sysroot
endif

CLIBS := $(_NDK_ROOT)/platforms/$(_APP_PLATFORM)/arch-$(_ARCH)/usr/lib

SRC := ./finally.cpp

MODULE := shell

CC := $(_NDK_ROOT)/toolchains/$(_TOOLCHAINS)-$(_TOOLCHAINS_VER)/prebuilt/windows-x86_64/bin/$(_TOOLCHAINS)-gcc
LD := $(_NDK_ROOT)/toolchains/$(_TOOLCHAINS)-$(_TOOLCHAINS_VER)/prebuilt/windows-x86_64/bin/$(_TOOLCHAINS)-ld

CFLAGS := \
	  -s \
	  -O2 \
	  -std=c11 \
	  -nostdlib \
	  -march=armv7-a \
	  -fno-exceptions \
	  -fno-unwind-tables \
	  -fno-stack-protector

INCLUDES := \
	-I$(SYS_INCLUDE) \
	-I$(SYS_INCLUDE)/$(_TOOLCHAINS)

PRE_DEFINE := -DDYNAMIC_CALL


compile:
	$(CC) -c -w $(CFLAGS) $(INCLUDES) $(PRE_DEFINE) $(SRC) -o $(MODULE).o


link:
	$(LD) -shared -T ldscript -l$(CLIBS)/libc.so -l$(CLIBS)/libz.so -l$(CLIBS)/libdl.so -l$(CLIBS)/liblog.so -l$(CLIBS)/libm.so $(MODULE).o -o $(MODULE).so

