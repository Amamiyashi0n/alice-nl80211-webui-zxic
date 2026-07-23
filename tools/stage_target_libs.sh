#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
	echo "usage: $0 OUTPUT_DIR" >&2
	exit 2
fi

out=$1
adb_port=${ADB_PORT:-5038}
serial=${ADB_SERIAL:-}

mkdir -p "$out"

finish_stage()
{
	ln -sf ld-uClibc.so.0 "$out/ld-uClibc.so"
	ln -sf libc.so.0 "$out/libc.so"
	ln -sf libdl.so.0 "$out/libdl.so"
	ln -sf libm.so.0 "$out/libm.so"
	ln -sf libpthread.so.0 "$out/libpthread.so"
	ln -sf librt.so.0 "$out/librt.so"
	ln -sf libgcc_s.so.1 "$out/libgcc_s.so"
	ln -sf libnl-3.so.200 "$out/libnl-3.so"
	ln -sf libnl-genl-3.so.200 "$out/libnl-genl-3.so"
	: >"$out/.ready"
}

if [ -f "$out/ld-uClibc.so.0" ] &&
	[ -f "$out/libc.so.0" ] &&
	[ -f "$out/libdl.so.0" ] &&
	[ -f "$out/libm.so.0" ] &&
	[ -f "$out/libpthread.so.0" ] &&
	[ -f "$out/librt.so.0" ] &&
	[ -f "$out/libgcc_s.so.1" ] &&
	[ -f "$out/libnl-3.so.200" ] &&
	[ -f "$out/libnl-genl-3.so.200" ]; then
	finish_stage
	exit 0
fi

if ! command -v adb >/dev/null 2>&1; then
	echo "missing adb; set DYNAMIC_LIB_DIR to a staged target /lib tree" >&2
	exit 1
fi

adb_cmd="adb -P $adb_port"

if [ -z "$serial" ]; then
	serial=$($adb_cmd devices | awk '$2 == "device" && $1 !~ /^emulator-/ { print $1; exit }')
fi

if [ -z "$serial" ]; then
	echo "no online non-emulator adb target found" >&2
	exit 1
fi

find_target_lib()
{
	pattern=$1
	$adb_cmd -s "$serial" shell "for f in /lib/$pattern; do printf '%s\\n' \"\$f\"; break; done" |
		tr -d '\r' | sed -n '1p'
}

pull_pattern()
{
	pattern=$1
	name=$2
	path=$(find_target_lib "$pattern")
	if [ -z "$path" ] || [ "$path" = "/lib/$pattern" ]; then
		echo "target library not found: $pattern" >&2
		exit 1
	fi
	$adb_cmd -s "$serial" pull "$path" "$out/$name" >/dev/null
}

pull_pattern 'ld-uClibc-*.so' ld-uClibc.so.0
pull_pattern 'libuClibc-*.so' libc.so.0
pull_pattern 'libdl-*.so' libdl.so.0
pull_pattern 'libm-*.so' libm.so.0
pull_pattern 'libpthread-*.so' libpthread.so.0
pull_pattern 'librt-*.so' librt.so.0
pull_pattern 'libnl-3.so.200.*' libnl-3.so.200
pull_pattern 'libnl-genl-3.so.200.*' libnl-genl-3.so.200

if [ ! -f "$out/libgcc_s.so.1" ]; then
	$adb_cmd -s "$serial" pull /lib/libgcc_s.so.1 "$out/libgcc_s.so.1" >/dev/null
fi

finish_stage
