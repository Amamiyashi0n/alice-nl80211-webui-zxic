#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SYSROOT=${SYSROOT:-"$ROOT_DIR/cross_toolchain/arm-buildroot-linux-uclibcgnueabi/sysroot"}
WPA_PROFILE=${WPA_PROFILE:-psk}
if [ "$WPA_PROFILE" = "psk" ]; then
	WPA_BUILD=${WPA_BUILD:-"$ROOT_DIR/.build/wpa-psk-2.4"}
	WPA_CONFIG=${WPA_CONFIG:-tools/wpa_psk.config}
elif [ "$WPA_PROFILE" = "full" ]; then
	WPA_BUILD=${WPA_BUILD:-"$ROOT_DIR/.build/wpa-build-2.4"}
	WPA_CONFIG=${WPA_CONFIG:-tools/wpa_mini.config}
else
	echo "WPA_PROFILE must be psk or full" >&2
	exit 2
fi
WPA_STAMP=${WPA_STAMP:-"$WPA_BUILD/.ready"}
WPA_CC=${WPA_CC:-arm-linux-gnueabi-gcc}
WPA_JOBS=${WPA_JOBS:-2}
WPA_URL=${WPA_URL:-https://w1.fi/releases/wpa_supplicant-2.4.tar.gz}
ARCHIVE=${WPA_ARCHIVE:-"$ROOT_DIR/.build/vendor/wpa_supplicant-2.4.tar.gz"}
SOURCE_DIR=${WPA_SOURCE_DIR:-"$ROOT_DIR/.build/vendor/wpa_supplicant-2.4"}

mkdir -p "$(dirname "$ARCHIVE")" "$WPA_BUILD"

if [ ! -f "$ARCHIVE" ]; then
	if command -v curl >/dev/null 2>&1; then
		curl -fL --retry 2 -o "$ARCHIVE" "$WPA_URL"
	elif command -v wget >/dev/null 2>&1; then
		wget -O "$ARCHIVE" "$WPA_URL"
	else
		echo "missing curl or wget; cannot fetch $WPA_URL" >&2
		exit 1
	fi
fi

if [ ! -f "$SOURCE_DIR/wpa_supplicant/Makefile" ]; then
	mkdir -p "$(dirname "$SOURCE_DIR")"
	tar -xzf "$ARCHIVE" -C "$(dirname "$SOURCE_DIR")"
fi

if [ ! -f "$WPA_BUILD/wpa_supplicant/Makefile" ]; then
	cp -a "$SOURCE_DIR/." "$WPA_BUILD/"
fi

case "$WPA_CONFIG" in
	/*) CONFIG_SOURCE="$WPA_CONFIG" ;;
	*) CONFIG_SOURCE="$ROOT_DIR/$WPA_CONFIG" ;;
esac
cp "$CONFIG_SOURCE" "$WPA_BUILD/wpa_supplicant/.config"

# wpa_supplicant 2.4 leaves wpa_config_get_all() outside NO_CONFIG_WRITE,
# even though that option removes parse_data.writer. The PSK engine has no
# configuration export path, so omit the unused function for this profile.
if [ "$WPA_PROFILE" = "psk" ] &&
	! grep -q 'WPA_MINI_NO_CONFIG_GET_ALL' "$WPA_BUILD/wpa_supplicant/config.c"; then
	patch -d "$WPA_BUILD" -p1 --fuzz=0 < "$ROOT_DIR/tools/wpa_psk.patch"
fi

# The PSK engine only accepts an SSID and a pre-derived PSK. Keep the
# upstream parser table from retaining unused WEP, EAP, P2P, and roaming
# configuration fields in this profile.
if [ "$WPA_PROFILE" = "psk" ] &&
	! grep -q 'WPA_MINI_PSK_FIELDS' "$WPA_BUILD/wpa_supplicant/config.c"; then
	patch -d "$WPA_BUILD" -p1 --fuzz=0 < "$ROOT_DIR/tools/wpa_psk_fields.patch"
fi

if [ "$WPA_PROFILE" = "psk" ] &&
	! grep -q 'ifndef CONFIG_NO_WMM_AC' "$WPA_BUILD/wpa_supplicant/Makefile"; then
	patch -d "$WPA_BUILD" -p1 --fuzz=0 < "$ROOT_DIR/tools/wpa_psk_wmm.patch"
fi

# The PSK profile is a station-only client. Drop nl80211 AP, monitor, and
# radiotap support while retaining the STA scan/auth/associate path.
if [ "$WPA_PROFILE" = "psk" ] &&
	! grep -q 'CONFIG_NO_NL80211_AP' "$WPA_BUILD/src/drivers/drivers.mak"; then
	patch -d "$WPA_BUILD" -p1 --fuzz=0 < "$ROOT_DIR/tools/wpa_psk_nl80211.patch"
fi

# The outer link collects every object below WPA_BUILD. Remove objects left
# by an older WPA configuration so they cannot silently increase the image.
find "$WPA_BUILD" -type f \( -name '*.o' -o -name '*.d' \) -delete
rm -f "$WPA_BUILD/wpa_supplicant/wpa_supplicant"

GCC_INCLUDE=${GCC_INTERNAL_INCLUDE:-$($WPA_CC -print-file-name=include)}
EXTRA_CFLAGS="-Os -ffunction-sections -fdata-sections -fno-stack-protector -U_FORTIFY_SOURCE -nostdinc -DCONFIG_ANSI_C_EXTRA -isystem $GCC_INCLUDE -isystem $SYSROOT/usr/include"
if [ "$WPA_PROFILE" = "psk" ]; then
	EXTRA_CFLAGS="$EXTRA_CFLAGS -DWPA_MINI_PSK_ENGINE"
fi

make -B -C "$WPA_BUILD/wpa_supplicant" -j "$WPA_JOBS" wpa_supplicant \
	CC="$WPA_CC --sysroot=$SYSROOT -B$SYSROOT/usr/lib/" \
	EXTRA_CFLAGS="$EXTRA_CFLAGS" \
	LDFLAGS="-static -Wl,--gc-sections -Wl,--allow-multiple-definition" \
	LIBNL_INC="$SYSROOT/usr/include/libnl3" \
	LIBS="-L$SYSROOT/usr/lib -lnl-genl-3 -lnl-3 -lpthread -lm -lrt"

mkdir -p "$(dirname "$WPA_STAMP")"
: >"$WPA_STAMP"
