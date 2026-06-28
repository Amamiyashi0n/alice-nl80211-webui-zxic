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
rm -f "$tmp"

app_size=$(wc -c <"$input" | tr -d ' ')
app_stamp=$(cksum "$input" | awk '{ print $1 "-" $2 }')

cat >"$tmp" <<SCRIPT
#!/bin/sh
set -eu

app_size=$app_size
app_stamp=$app_stamp
SCRIPT

cat >>"$tmp" <<'SCRIPT'
self=$0
out=${WPA_MINI_EXTRACT:-/tmp/wpa_mini}
tmp="${out}.$$"
stamp="${out}.stamp"
marker="__WPA_MINI_PAYLOAD_BELOW__"

trap '' HUP
mount -o remount,exec /tmp 2>/dev/null || true
rm -f "$tmp"

file_size()
{
	set -- $(wc -c <"$1" 2>/dev/null || echo 0)
	echo "${1:-0}"
}

if [ "${WPA_MINI_FORCE_EXTRACT:-0}" != 1 ] && [ -x "$out" ] && [ "$(file_size "$out")" = "$app_size" ]; then
	if [ "$(cat "$stamp" 2>/dev/null || true)" = "$app_stamp" ]; then
		exec "$out" "$@"
		echo "exec failed: $out" >&2
		exit 127
	fi
fi

if ! command -v awk >/dev/null 2>&1; then
	echo "need awk" >&2
	exit 1
fi

decode_payload()
{
	LC_ALL=C awk -v marker="$marker" '
	function emit(v) {
		printf "\\%03o", v
		n++
		if (n >= 256) {
			printf "\n"
			n = 0
		}
	}
	BEGIN {
		chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
		for (i = 1; i <= length(chars); i++)
			dec[substr(chars, i, 1)] = i - 1
		found = 0
		n = 0
	}
	$0 == marker {
		found = 1
		next
	}
	!found {
		next
	}
	{
		gsub(/[ \t\r]/, "", $0)
		for (i = 1; i <= length($0); i += 4) {
			c1 = substr($0, i, 1)
			c2 = substr($0, i + 1, 1)
			c3 = substr($0, i + 2, 1)
			c4 = substr($0, i + 3, 1)
			if (c1 == "" || c2 == "")
				next
			v1 = dec[c1]
			v2 = dec[c2]
			if (c3 == "=" || c3 == "")
				v3 = 0
			else
				v3 = dec[c3]
			if (c4 == "=" || c4 == "")
				v4 = 0
			else
				v4 = dec[c4]
			emit(int(v1 * 4 + v2 / 16))
			if (c3 != "=" && c3 != "")
				emit(int((v2 % 16) * 16 + v3 / 4))
			if (c4 != "=" && c4 != "")
				emit(int((v3 % 4) * 64 + v4))
		}
	}
	END {
		if (n > 0)
			printf "\n"
	}
	' "$self" | while IFS= read -r line || [ -n "$line" ]; do
		printf "%b" "$line"
	done
}

extracted=0
if command -v zcat >/dev/null 2>&1; then
	if decode_payload | zcat >"$tmp"; then
		extracted=1
	fi
elif command -v gunzip >/dev/null 2>&1; then
	if decode_payload | gunzip -c >"$tmp"; then
		extracted=1
	fi
elif command -v busybox >/dev/null 2>&1; then
	if decode_payload | busybox gunzip -c >"$tmp"; then
		extracted=1
	fi
else
	echo "need zcat or gunzip" >&2
	exit 1
fi

if [ "$extracted" != 1 ] || [ ! -s "$tmp" ]; then
	rm -f "$tmp"
	echo "extract failed" >&2
	exit 1
fi

chmod 755 "$tmp"
mv "$tmp" "$out"
echo "$app_stamp" >"$stamp" 2>/dev/null || true
exec "$out" "$@"
echo "exec failed: $out" >&2
exit 127

__WPA_MINI_PAYLOAD_BELOW__
SCRIPT

gzip -9 -n -c "$input" | base64 >>"$tmp"
chmod 755 "$tmp"
mv "$tmp" "$output"
