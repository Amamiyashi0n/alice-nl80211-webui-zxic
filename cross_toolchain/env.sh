#!/bin/bash
# Cross-compilation toolchain setup
# Usage: source env.sh

CROSS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export PATH="${CROSS_ROOT}/bin:${PATH}"

# Set sysroot for convenience (can also use --sysroot= on gcc cmdline)
export SYSROOT="${CROSS_ROOT}/arm-buildroot-linux-uclibcgnueabi/sysroot"

# Shorthand
export CC="arm-buildroot-linux-uclibcgnueabi-gcc --sysroot=${SYSROOT}"
export CXX="arm-buildroot-linux-uclibcgnueabi-g++ --sysroot=${SYSROOT}"
export LD="arm-buildroot-linux-uclibcgnueabi-ld"
export STRIP="arm-buildroot-linux-uclibcgnueabi-strip"
export AR="arm-buildroot-linux-uclibcgnueabi-ar"

echo "Cross toolchain ready: arm-buildroot-linux-uclibcgnueabi-gcc (ARM926EJ-S, soft-float, uClibc)"
echo "Sysroot: ${SYSROOT}"
