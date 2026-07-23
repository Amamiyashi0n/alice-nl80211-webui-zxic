CROSS_ROOT ?= $(CURDIR)/cross_toolchain
SYSROOT ?= $(CROSS_ROOT)/arm-buildroot-linux-uclibcgnueabi/sysroot
TARGET_TRIPLE ?= arm-linux-gnueabi
CROSS_COMPILE ?= $(TARGET_TRIPLE)-
TARGET_CC ?= $(TARGET_TRIPLE)-gcc
TARGET_STRIP ?= $(TARGET_TRIPLE)-strip
TARGET_OBJCOPY ?= $(TARGET_TRIPLE)-objcopy
TARGET_SIZE ?= $(TARGET_TRIPLE)-size
GCC_INTERNAL_INCLUDE ?= $(shell $(TARGET_CC) -print-file-name=include)

SRC_DIR := src
OUT_DIR := output
BUILD_DIR := .build
TARGET := wpa_mini
TARGET_BIN := $(OUT_DIR)/$(TARGET)
TARGET_RUN := $(OUT_DIR)/$(TARGET).run
TARGET_SRC := $(SRC_DIR)/$(TARGET).c
DYNAMIC_RUNTIME_SRC := $(SRC_DIR)/dynamic_runtime.c
SELF_EXTRACT := tools/make_self_extract.sh
ASSET_EMBED := tools/embed_asset.py
AVATAR_SRC := pic/miku_compressed.jpg
AVATAR_HEADER := $(BUILD_DIR)/avatar_asset.h
SPONSOR_SRC := pic/sponsor_clean.jpg
SPONSOR_HEADER := $(BUILD_DIR)/sponsor_asset.h
WPA_PROFILE ?= psk
ifeq ($(WPA_PROFILE),psk)
WPA_BUILD ?= $(BUILD_DIR)/wpa-psk-2.4
WPA_CONFIG := tools/wpa_psk.config
WPA_ENGINE_SOURCE := $(SRC_DIR)/wpa_psk_engine.c
WPA_ENGINE_MAIN_OBJ := $(BUILD_DIR)/wpa_psk_engine.o
else ifeq ($(WPA_PROFILE),full)
WPA_BUILD ?= $(BUILD_DIR)/wpa-build-2.4
WPA_CONFIG := tools/wpa_mini.config
WPA_ENGINE_SOURCE :=
WPA_ENGINE_MAIN_OBJ := $(BUILD_DIR)/wpa_engine_main.o
else
$(error WPA_PROFILE must be psk or full)
endif
WPA_MAIN_OBJ := $(WPA_BUILD)/wpa_supplicant/main.o
WPA_READY := $(WPA_BUILD)/.ready
WPA_PREP := tools/build_wpa_engine.sh
RUNTIME_STAGE := tools/stage_target_libs.sh
WPA_OBJECTS = $(shell find $(WPA_BUILD) -name '*.o' \
	! -path '*/wpa_supplicant/main*.o' \
	! -path '*/wpa_supplicant/wpa_cli.o' \
	! -path '*/wpa_supplicant/wpa_passphrase.o' \
	! -path '*/src/utils/edit_simple.o' 2>/dev/null | sort)

ifeq ($(origin CC),default)
CC := $(TARGET_CC) --sysroot=$(SYSROOT) -B$(SYSROOT)/usr/lib/
endif

ifneq ($(filter default undefined,$(origin STRIP)),)
STRIP := $(TARGET_STRIP)
endif

ifneq ($(filter default undefined,$(origin OBJCOPY)),)
OBJCOPY := $(TARGET_OBJCOPY)
endif

ifneq ($(filter default undefined,$(origin CFLAGS)),)
CFLAGS := -Os -Wall -Wextra -ffunction-sections -fdata-sections \
	-fno-stack-protector -U_FORTIFY_SOURCE -nostdinc \
	-isystem $(GCC_INTERNAL_INCLUDE) -isystem $(SYSROOT)/usr/include
endif
CPPFLAGS ?=
LINK_MODE ?= dynamic
DYNAMIC_LIB_DIR ?= $(BUILD_DIR)/dynamic-lib
DYNAMIC_LINKER ?= /lib/ld-uClibc.so.0
ADB_PORT ?= 5038
JOBS ?= 2

ifeq ($(LINK_MODE),dynamic)
RUNTIME_READY := $(DYNAMIC_LIB_DIR)/.ready
LDFLAGS ?= -Wl,--gc-sections \
	-Wl,--dynamic-linker=$(DYNAMIC_LINKER) \
	-Wl,-rpath-link,$(DYNAMIC_LIB_DIR) \
	-Wl,--allow-shlib-undefined -Wl,--no-as-needed
LDLIBS ?= -L$(DYNAMIC_LIB_DIR) -L$(SYSROOT)/usr/lib \
	-lnl-genl-3 -lnl-3 -lpthread -lm -lrt -ldl -shared-libgcc
else ifeq ($(LINK_MODE),static)
RUNTIME_READY :=
LDFLAGS ?= -static -Wl,--gc-sections
LDLIBS ?= -L$(SYSROOT)/usr/lib -lnl-genl-3 -lnl-3 -lpthread -lm -lrt
else
$(error LINK_MODE must be dynamic or static)
endif

ifeq ($(LINK_MODE),dynamic)
CPPFLAGS += -DWPA_MINI_DYNAMIC
endif
DEBUG ?= 0
ENGINE_WRAP_CPPFLAGS :=
ENGINE_WRAP_LDFLAGS :=

ifeq ($(DEBUG),1)
ENGINE_WRAP_CPPFLAGS += -DWPA_MINI_WRAP_ENGINE
ENGINE_WRAP_LDFLAGS += \
	-Wl,--wrap=wpa_msg_register_cb \
	-Wl,--wrap=wpa_supplicant_init \
	-Wl,--wrap=wpa_supplicant_add_iface \
	-Wl,--wrap=wpa_config_read \
	-Wl,--wrap=wpa_config_set \
	-Wl,--wrap=wpa_config_process_global \
	-Wl,--wrap=wpa_supplicant_driver_init \
	-Wl,--wrap=wpa_supplicant_update_mac_addr \
	-Wl,--wrap=wpa_supplicant_init_wpa \
	-Wl,--wrap=wpa_supplicant_init_eapol \
	-Wl,--wrap=wpa_supplicant_ctrl_iface_init \
	-Wl,--wrap=wpa_bss_init \
	-Wl,--wrap=wpa_supplicant_run \
	-Wl,--wrap=netlink_init \
	-Wl,--wrap=l2_packet_init \
	-Wl,--wrap=l2_packet_init_bridge \
	-Wl,--wrap=wpa_driver_nl80211_capa \
	-Wl,--wrap=wpa_driver_nl80211_get_macaddr \
	-Wl,--wrap=wpa_driver_nl80211_set_mode \
	-Wl,--wrap=nl80211_get_wiphy_index \
	-Wl,--wrap=send_and_recv_msgs \
	-Wl,--wrap=rfkill_init \
	-Wl,--wrap=linux_iface_up \
	-Wl,--wrap=linux_set_iface_flags \
	-Wl,--wrap=linux_get_ifhwaddr \
	-Wl,--wrap=if_nametoindex \
	-Wl,--wrap=genl_ctrl_resolve
endif

.PHONY: all clean distclean strip size run wpa-engine runtime

all: $(TARGET_BIN)

$(OUT_DIR):
	mkdir -p $@

$(BUILD_DIR):
	mkdir -p $@

$(WPA_READY): $(WPA_PREP) $(WPA_CONFIG) | $(BUILD_DIR)
	SYSROOT="$(SYSROOT)" WPA_BUILD="$(WPA_BUILD)" WPA_STAMP="$@" \
	WPA_PROFILE="$(WPA_PROFILE)" WPA_CONFIG="$(WPA_CONFIG)" \
	WPA_CC="$(TARGET_CC)" WPA_JOBS="$(JOBS)" sh "$(WPA_PREP)"

$(WPA_MAIN_OBJ): $(WPA_READY)
	@test -f "$@"

wpa-engine: $(WPA_ENGINE_MAIN_OBJ)

ifeq ($(LINK_MODE),dynamic)
$(RUNTIME_READY): $(RUNTIME_STAGE) | $(BUILD_DIR)
	ADB_PORT="$(ADB_PORT)" ADB_SERIAL="$(ADB_SERIAL)" \
	sh "$(RUNTIME_STAGE)" "$(DYNAMIC_LIB_DIR)"

runtime: $(RUNTIME_READY)
else
runtime:
	@true
endif

ifeq ($(WPA_PROFILE),psk)
$(WPA_ENGINE_MAIN_OBJ): $(WPA_READY) $(WPA_ENGINE_SOURCE) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) -DWPA_MINI_PSK_ENGINE $(CFLAGS) \
		-DCONFIG_NO_STDOUT_DEBUG -DCONFIG_NO_WPA_MSG \
		-DCONFIG_NO_CONFIG_WRITE -DCONFIG_NO_CONFIG_BLOBS \
		-DCONFIG_DRIVER_NL80211 -DCONFIG_LIBNL20 \
		-DCONFIG_CRYPTO_INTERNAL -DCONFIG_INTERNAL_LIBTOMMATH \
		-DLTM_FAST -DCONFIG_SME \
		-I$(WPA_BUILD)/wpa_supplicant -I$(WPA_BUILD)/src \
		-I$(SYSROOT)/usr/include/libnl3 \
		-I$(WPA_BUILD)/src/utils -c $(WPA_ENGINE_SOURCE) -o $@
else
$(WPA_ENGINE_MAIN_OBJ): $(WPA_MAIN_OBJ) $(WPA_READY) | $(BUILD_DIR)
	$(OBJCOPY) --redefine-sym main=wpa_engine_main $< $@
endif

$(AVATAR_HEADER): $(AVATAR_SRC) $(ASSET_EMBED) | $(BUILD_DIR)
	$(ASSET_EMBED) $(AVATAR_SRC) $@ avatar_image image/jpeg

$(SPONSOR_HEADER): $(SPONSOR_SRC) $(ASSET_EMBED) | $(BUILD_DIR)
	$(ASSET_EMBED) $(SPONSOR_SRC) $@ sponsor_image image/jpeg



$(TARGET_BIN): $(TARGET_SRC) $(DYNAMIC_RUNTIME_SRC) \
	$(AVATAR_HEADER) $(SPONSOR_HEADER) \
	$(WPA_ENGINE_MAIN_OBJ) $(WPA_READY) $(RUNTIME_READY) | $(OUT_DIR)
	$(CC) $(CPPFLAGS) $(ENGINE_WRAP_CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(ENGINE_WRAP_LDFLAGS) -o $@ $(TARGET_SRC) $(DYNAMIC_RUNTIME_SRC) $(WPA_ENGINE_MAIN_OBJ) $(WPA_OBJECTS) $(LDLIBS)

$(TARGET_RUN): $(TARGET_BIN) $(SELF_EXTRACT) strip | $(OUT_DIR)
	$(SELF_EXTRACT) $(TARGET_BIN) $@

strip: $(TARGET_BIN)
	$(STRIP) $(TARGET_BIN)

run: $(TARGET_RUN)

size: $(TARGET_BIN)
	$(TARGET_SIZE) $(TARGET_BIN)

clean:
	rm -f $(TARGET_BIN)
	rm -f $(TARGET_RUN)
	rm -f $(OUT_DIR)/wpa_engine_main.o
	rm -f $(AVATAR_HEADER)
	rm -f $(SPONSOR_HEADER)
	rm -rf $(BUILD_DIR)

distclean:
	rm -rf $(OUT_DIR)
