#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
	echo "usage: $0 INPUT OUTPUT" >&2
	exit 2
fi

input=$1
output=$2

if [ ! -f "$input" ]; then
	echo "missing input: $input" >&2
	exit 1
fi

tmp="${output}.tmp"
zip_tmp="${output}.ziptmp"
rm -f "$tmp" "$zip_tmp"

app_size=$(wc -c <"$input" | tr -d ' ')
app_stamp=$(cksum "$input" | awk '{ print $1 "-" $2 }')

python3 - "$input" "$zip_tmp" <<'PY'
import sys
import zipfile

src, dst = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zf:
    zf.write(src, "wpa_mini")
PY

cat >"$tmp" <<SCRIPT
#!/bin/sh
set -eu

app_size=$app_size
app_stamp=$app_stamp
SCRIPT

cat >>"$tmp" <<'SCRIPT'
self=$0
if [ "${self#/}" = "$self" ]; then
	case "$self" in
	*/*)
		self_dir=${self%/*}
		self_base=${self##*/}
		abs_dir=$(cd "$self_dir" 2>/dev/null && pwd) && self=$abs_dir/$self_base
		;;
	*)
		self=$(pwd)/$self
		;;
	esac
fi
out=${WPA_MINI_EXTRACT:-/tmp/wpa_mini}
tmp="${out}.$$"
zip="${out}.$$.zip"
stamp="${out}.stamp"
marker="__WPA_MINI_ZIP_PAYLOAD_BELOW__"

trap '' HUP
mount -o remount,exec /tmp 2>/dev/null || true
rm -f "$tmp" "$zip"

file_size()
{
	set -- $(wc -c <"$1" 2>/dev/null || echo 0)
	echo "${1:-0}"
}

if [ "${WPA_MINI_FORCE_EXTRACT:-0}" != 1 ] && [ -x "$out" ] && [ "$(file_size "$out")" = "$app_size" ]; then
	if [ "$(cat "$stamp" 2>/dev/null || true)" = "$app_stamp" ]; then
		WPA_MINI_RUN_SOURCE=$self exec "$out" "$@"
		echo "exec failed: $out" >&2
		exit 127
	fi
fi

if ! command -v sed >/dev/null 2>&1; then
	echo "need sed" >&2
	exit 1
fi
if ! command -v unzip >/dev/null 2>&1; then
	echo "need unzip" >&2
	exit 1
fi

sed "1,/^$marker$/d" "$self" >"$zip"
if [ ! -s "$zip" ]; then
	rm -f "$zip"
	echo "missing zip payload" >&2
	exit 1
fi

if ! unzip -p "$zip" wpa_mini >"$tmp"; then
	rm -f "$tmp" "$zip"
	echo "extract failed" >&2
	exit 1
fi
rm -f "$zip"

if [ ! -s "$tmp" ]; then
	rm -f "$tmp"
	echo "extract failed" >&2
	exit 1
fi

chmod 755 "$tmp"
mv "$tmp" "$out"
echo "$app_stamp" >"$stamp" 2>/dev/null || true
WPA_MINI_RUN_SOURCE=$self exec "$out" "$@"
echo "exec failed: $out" >&2
exit 127

__WPA_MINI_ZIP_PAYLOAD_BELOW__
SCRIPT

cat "$zip_tmp" >>"$tmp"
rm -f "$zip_tmp"
chmod 755 "$tmp"
mv "$tmp" "$output"
