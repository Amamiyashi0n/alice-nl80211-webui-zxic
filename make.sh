#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT_DIR"

CROSS_ROOT=${CROSS_ROOT:-"$ROOT_DIR/cross_toolchain"}
TOOLCHAIN_BIN="$CROSS_ROOT/bin"

if [ ! -d "$TOOLCHAIN_BIN" ]; then
	echo "错误：交叉工具链目录不存在: $TOOLCHAIN_BIN" >&2
	exit 1
fi

if [ ! -x "$ROOT_DIR/tools/make_self_extract.sh" ]; then
	echo "错误：缺少自解压构建脚本: tools/make_self_extract.sh" >&2
	exit 1
fi

export PATH="$TOOLCHAIN_BIN:$PATH"

make output/wpa_mini
make strip
make output/wpa_mini.run

echo "构建完成："
ls -lh output/wpa_mini output/wpa_mini.run
