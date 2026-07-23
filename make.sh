#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT_DIR"

TARGET_CC=${TARGET_CC:-arm-linux-gnueabi-gcc}

if ! command -v "$TARGET_CC" >/dev/null 2>&1; then
	echo "错误：找不到 ARM 交叉编译器: $TARGET_CC" >&2
	exit 1
fi

if [ ! -x "$ROOT_DIR/tools/make_self_extract.sh" ]; then
	echo "错误：缺少自解压构建脚本: tools/make_self_extract.sh" >&2
	exit 1
fi

make output/wpa_mini.run

echo "构建完成："
ls -lh output/wpa_mini output/wpa_mini.run
