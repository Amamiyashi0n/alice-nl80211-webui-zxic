CROSS_ROOT ?= $(CURDIR)/cross_toolchain
SYSROOT ?= $(CROSS_ROOT)/arm-buildroot-linux-uclibcgnueabi/sysroot
CROSS_COMPILE ?= arm-buildroot-linux-uclibcgnueabi-
WPA_BUILD ?= /home/amamiya/repos/buildroot-2015.08.1/output/build/wpa_supplicant-2.4

SRC_DIR := src
OUT_DIR := output
BUILD_DIR := .build
TARGET := wpa_mini
TARGET_BIN := $(OUT_DIR)/$(TARGET)
TARGET_RUN := $(OUT_DIR)/$(TARGET).run
TARGET_SRC := $(SRC_DIR)/$(TARGET).c
SELF_EXTRACT := tools/make_self_extract.sh
ASSET_EMBED := tools/embed_asset.py
AVATAR_SRC := pic/miku_compressed.jpg
AVATAR_HEADER := $(BUILD_DIR)/avatar_asset.h
SPONSOR_SRC := pic/sponsor_clean.jpg
SPONSOR_HEADER := $(BUILD_DIR)/sponsor_asset.h
WPA_MAIN_OBJ := $(WPA_BUILD)/wpa_supplicant/main.o
WPA_ENGINE_MAIN_OBJ := $(BUILD_DIR)/wpa_engine_main.o
WPA_OBJECTS := $(shell find $(WPA_BUILD) -name '*.o' \
	! -path '*/wpa_supplicant/main.o' \
	! -path '*/wpa_supplicant/wpa_cli.o' \
	! -path '*/wpa_supplicant/wpa_passphrase.o' 2>/dev/null | sort)

ifeq ($(origin CC),default)
CC := $(CROSS_COMPILE)gcc --sysroot=$(SYSROOT)
endif

ifeq ($(origin STRIP),undefined)
STRIP := $(CROSS_COMPILE)strip
endif

OBJCOPY ?= $(CROSS_COMPILE)objcopy

CFLAGS ?= -Os -Wall -Wextra -ffunction-sections -fdata-sections
CPPFLAGS ?=
LDFLAGS ?= -static -Wl,--gc-sections
LDLIBS ?= -L$(SYSROOT)/usr/lib -lnl-genl-3 -lnl-3 -lpthread -lm -lrt
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

.PHONY: all clean distclean strip size run

all: $(TARGET_BIN)

$(OUT_DIR):
	mkdir -p $@

$(BUILD_DIR):
	mkdir -p $@

$(WPA_ENGINE_MAIN_OBJ): $(WPA_MAIN_OBJ) | $(BUILD_DIR)
	$(OBJCOPY) --redefine-sym main=wpa_engine_main $< $@

$(AVATAR_HEADER): $(AVATAR_SRC) $(ASSET_EMBED) | $(BUILD_DIR)
	$(ASSET_EMBED) $(AVATAR_SRC) $@ avatar_image image/jpeg

$(SPONSOR_HEADER): $(SPONSOR_SRC) $(ASSET_EMBED) | $(BUILD_DIR)
	$(ASSET_EMBED) $(SPONSOR_SRC) $@ sponsor_image image/jpeg

$(TARGET_BIN): $(TARGET_SRC) $(AVATAR_HEADER) $(SPONSOR_HEADER) $(WPA_ENGINE_MAIN_OBJ) $(WPA_OBJECTS) | $(OUT_DIR)
	$(CC) $(CPPFLAGS) $(ENGINE_WRAP_CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(ENGINE_WRAP_LDFLAGS) -o $@ $(TARGET_SRC) $(WPA_ENGINE_MAIN_OBJ) $(WPA_OBJECTS) $(LDLIBS)

$(TARGET_RUN): $(TARGET_BIN) $(SELF_EXTRACT) | $(OUT_DIR)
	$(SELF_EXTRACT) $(TARGET_BIN) $@

strip: $(TARGET_BIN)
	$(STRIP) $(TARGET_BIN)

run: $(TARGET_RUN)

size: $(TARGET_BIN)
	$(CROSS_COMPILE)size $(TARGET_BIN)

clean:
	rm -f $(TARGET_BIN)
	rm -f $(TARGET_RUN)
	rm -f $(OUT_DIR)/wpa_engine_main.o
	rm -f $(AVATAR_HEADER)
	rm -f $(SPONSOR_HEADER)
	rm -rf $(BUILD_DIR)

distclean:
	rm -rf $(OUT_DIR)
