# Buildroot 2015.08.1 — 完整编译上下文 & wpa_supplicant 精简记录

## 1. 编译环境概况

| 项目 | 值 |
|---|---|
| Buildroot 版本 | 2015.08.1 |
| 目标架构 | ARM (arm926ej-s, ARMv5TE) |
| 浮点 | soft-float |
| ABI | aapcs-linux |
| C 库 | uClibc |
| 工具链 | gcc 4.9.3 + binutils 2.24 |
| 内核 | Linux 3.4.108 |
| 主机 | x86_64, Ubuntu |

### 1.1 源码目录布局

```
buildroot-2015.08.1/
├── .config              # Buildroot 配置 (Kconfig)
├── package/             # 各软件包构建脚本 (*.mk + Config.in)
│   ├── wpa_supplicant/  # wpa_supplicant 构建规则
│   └── ...
├── output/
│   ├── host/            # 主机端工具链和工具
│   │   └── usr/
│   │       ├── bin/     # arm-*-gcc, arm-*-ld ...
│   │       ├── lib/     # libmpfr, libmpc, libgmp ...
│   │       ├── libexec/ # cc1, collect2 ...
│   │       └── arm-buildroot-linux-uclibcgnueabi/
│   │           ├── bin/  # 目标 binutils (as, ld, strip...)
│   │           └── sysroot/  # 目标系统根目录
│   ├── build/           # 各包构建目录
│   ├── target/          # 最终目标文件系统
│   └── images/          # 输出镜像 (rootfs.tar)
└── dl/                  # 下载的源码包
```

---

## 2. 工具链迁移问题 (RPATH 修复)

### 2.1 问题根因

工具链最初在 `/root/buildroot-2015.08.1/` 下编译，所有二进制文件的 RPATH 硬编码为：

```
/root/buildroot-2015.08.1/output/host/usr/lib
```

项目迁移到 `/home/amamiya/repos/buildroot-2015.08.1/` 后，`make` 失败：

```
cc1: error while loading shared libraries: libmpfr.so.4: cannot open
configure: error: C compiler cannot create executables
```

### 2.2 诊断过程

```bash
# 1. 查看 config.log，发现关键行：
# cc1: error while loading shared libraries: libmpfr.so.4: not found

# 2. 检查 cc1 的 RPATH：
readelf -d libexec/gcc/arm-*/4.9.3/cc1 | grep RPATH
# → RPATH: [/root/buildroot-2015.08.1/output/host/usr/lib]

# 3. 检查 /root 权限：
stat -c '%a %n' /root
# → 700 (无法被非 root 用户遍历)

# 4. 验证 libmpfr.so.4 存在但无法被访问：
find output/host/usr/lib -name "libmpfr*"
# → 文件存在，但 RPATH 无法解析

# 5. 检查 /root/buildroot-2015.08.1 符号链接：
sudo ls -la /root/buildroot-2015.08.1
# → lrwxrwxrwx root → /home/amamiya/repos/buildroot-2015.08.1
#    符号链接存在，但因 /root 为 700 无法遍历
```

### 2.3 受影响的组件

| 组件 | 数量 | 具体影响 |
|---|---|---|
| RPATH 二进制 | ~60+ | gcc, cc1, collect2, lto1, as, ld, nm, strip, objdump, readelf, strings, ar, ranlib, cpp, gcov, c++filt, pkgconf, faked, m4, tr |
| .so 共享库 (带 RPATH) | 6 | libmpfr.so.4, libmpc.so.3, libgmp.so.10, libltdl.so.7, libfakeroot-0.so, libcap.so.2 |
| pkg-config 搜索路径 | 2 | `/root/.../lib/pkgconfig`, `/root/.../share/pkgconfig` |
| .pc 文件中的 -L 路径 | 多个 | libnl, zlib, ncurses 等 |

### 2.4 解决方案

**方案 A（采用）**：`sudo chmod 701 /root`

允许 "other" 遍历 /root（execute 但不可读），使动态链接器可以沿符号链接找到实际库文件。最小侵入性。

**方案 B（备选）**：`LD_LIBRARY_PATH=/path/to/host/usr/lib make`

Buildroot 的 `support/dependencies/dependencies.sh:14-27` 会检查 LD_LIBRARY_PATH 中的以下模式并拒绝执行：
- `::` (空组件 = CWD)
- `:.:` (显式 CWD)
- 开头或结尾为 `:` 或 `.:`
- 结尾为 `:` (尾部冒号等于 CWD)

因此设置时必须避免尾部 `:`。如 `export LD_LIBRARY_PATH=/path/to/lib`（不带 `:$LD_LIBRARY_PATH` 追加）。

### 2.5 第一次编译流程

```
make
  → libnl 3.2.26 Configuring   ✓ (LD_LIBRARY_PATH 生效)
  → libnl Building              ✓
  → libnl Installing            ✓
  → iw 4.1 Building             ✗ (pkg-config 找不到 libnl-3.0)
     原因: pkgconf 的搜索路径指向 /root/...，/root 权限 700 导致遍历失败
  → 修复 /root 权限后重新 make  ✓
  → wpa_supplicant Building     ✓
  → Finalizing target directory ✓
  → rootfs.tar generated        ✓ (6.9MB)
```

### 2.6 pkgconf 硬编码路径

```bash
# 验证 pkgconf 内置搜索路径
pkg-config --variable pc_path pkg-config
# → /root/buildroot-2015.08.1/output/host/usr/lib/pkgconfig:
#   /root/buildroot-2015.08.1/output/host/usr/share/pkgconfig

# 且二进制内部有硬编码字符串：
strings pkgconf | grep root
# → /root/buildroot-2015.08.1/output/host/usr/lib
# → /root/buildroot-2015.08.1/output/host/usr/include
```

这两个路径在 `chmod 701 /root` 后均可正确解析。

---

## 3. wpa_supplicant 精简分析

### 3.1 目标场景

```
STA 模式连接 WPA/WPA2-PSK WiFi
驱动: nl80211 (via libnl)
接口: wlan0-vxd
不需要: 企业认证 / WPS / AP / P2P / HS20
```

### 3.2 Buildroot 菜单配置 (`.config`)

```
BR2_PACKAGE_WPA_SUPPLICANT=y
# BR2_PACKAGE_WPA_SUPPLICANT_AP_SUPPORT is not set    # 不需要 AP
# BR2_PACKAGE_WPA_SUPPLICANT_EAP is not set           # 不需要企业认证
# BR2_PACKAGE_WPA_SUPPLICANT_HOTSPOT is not set        # 不需要 HS20
# BR2_PACKAGE_WPA_SUPPLICANT_DEBUG_SYSLOG is not set   # 不需要 syslog
# BR2_PACKAGE_WPA_SUPPLICANT_WPS is not set            # 不需要 WPS
# BR2_PACKAGE_WPA_SUPPLICANT_CLI is not set            # 当前交付不需要 wpa_cli
# BR2_PACKAGE_WPA_SUPPLICANT_PASSPHRASE is not set     # 不需要 (可用明文 psk=)
```

### 3.3 wpa_supplicant.mk 完整修改

文件：`package/wpa_supplicant/wpa_supplicant.mk`

**修改前**：
```makefile
WPA_SUPPLICANT_CONFIG_ENABLE = \
    CONFIG_IEEE80211AC      \
    CONFIG_IEEE80211N       \
    CONFIG_IEEE80211R       \
    CONFIG_INTERNAL_LIBTOMMATH \
    CONFIG_DEBUG_FILE

WPA_SUPPLICANT_CONFIG_DISABLE = \
    CONFIG_SMARTCARD
```

**修改后**：
```makefile
WPA_SUPPLICANT_CONFIG_ENABLE = \
    CONFIG_CTRL_IFACE           \
    CONFIG_INTERNAL_LIBTOMMATH  \
    CONFIG_INTERNAL_LIBTOMMATH_FAST \
    CONFIG_NO_STDOUT_DEBUG      \
    CONFIG_NO_CONFIG_WRITE      \
    CONFIG_NO_CONFIG_BLOBS

WPA_SUPPLICANT_CONFIG_DISABLE = \
    CONFIG_DRIVER_WEXT          \
    CONFIG_DRIVER_WIRED         \
    CONFIG_IEEE8021X_EAPOL      \
    CONFIG_PEERKEY              \
    CONFIG_PKCS12               \
    CONFIG_IEEE80211R           \
    CONFIG_IEEE80211N           \
    CONFIG_IEEE80211AC          \
    CONFIG_DEBUG_FILE           \
    CONFIG_SMARTCARD            \
    CONFIG_CTRL_IFACE_DBUS      \
    CONFIG_CTRL_IFACE_DBUS_NEW  \
    CONFIG_CTRL_IFACE_DBUS_INTRO
```

### 3.4 sed 前缀匹配缺陷

**问题**：`CONFIG_CTRL_IFACE` 被加入 ENABLE 列表后，sed 命令：
```
s/^#\(CONFIG_CTRL_IFACE\)/\1/
```
会错误匹配到 `#CONFIG_CTRL_IFACE_DBUS`、`#CONFIG_CTRL_IFACE_DBUS_NEW`、
`#CONFIG_CTRL_IFACE_DBUS_INTRO`（都以此为前缀），导致 DBus 代码被意外编译。

**症状**：`fatal error: dbus/dbus.h: No such file or directory`

**修复**：在 DISABLE 列表中显式添加这三个 DBus 相关的 CONFIG_ 项。

### 3.5 crypto 选择

`wpa_supplicant/Makefile` 第 1031-1032 行：
```makefile
ifndef CONFIG_CRYPTO
CONFIG_CRYPTO=internal
endif
```

当 `CONFIG_TLS=internal` 时，`CONFIG_CRYPTO` 自动默认 `internal`，
无需依赖 OpenSSL。

### 3.6 体积对比

| 二进制 | 原始 (strip) | 第一阶段 | 最终 (strip) | 总缩减 |
|---|---|---|---|---|
| wpa_supplicant | 619K | 520K | **402K** | **-217K (-35%)** |

**两阶段优化**：
1. 第一阶段：移除驱动/disabling EAP/AP/WPS/P2P/r/n/ac → 520K
2. 第二阶段：`NO_STDOUT_DEBUG` + `NO_CONFIG_WRITE` + `NO_CONFIG_BLOBS` → 402K

**各措施贡献估算**：
| 措施 | 约省 |
|---|---|
| 移除所有 EAP 方法 | ~100K |
| 移除 AP/P2P/WPS 支持 | ~50K |
| 只保留 nl80211 驱动 | ~30K |
| 移除 802.11r/n/ac | ~20K |
| `CONFIG_NO_STDOUT_DEBUG` | ~35K |
| `CONFIG_NO_CONFIG_WRITE` | ~3.5K |
| `CONFIG_NO_CONFIG_BLOBS` | ~1.5K |

### 3.7 wpa_supplicant .config 最终生效项

```ini
# 仅 nl80211 驱动
CONFIG_DRIVER_NL80211=y
CONFIG_LIBNL32=y

# 控制接口
CONFIG_CTRL_IFACE=y
CONFIG_BACKEND=file

# Internal crypto
CONFIG_TLS=internal
CONFIG_INTERNAL_LIBTOMMATH=y
CONFIG_INTERNAL_LIBTOMMATH_FAST=y

# 体积优化
CONFIG_NO_STDOUT_DEBUG=y
CONFIG_NO_CONFIG_WRITE=y
CONFIG_NO_CONFIG_BLOBS=y
```

### 3.8 使用示例

```bash
# STA 连接 WiFi
wpa_supplicant -Dnl80211 -iwlan0-vxd -c/etc/wpa_supplicant.conf -B

# 配置文件 /etc/wpa_supplicant.conf:
# ctrl_interface=/var/run/wpa_supplicant
# update_config=1
# network={
#     ssid="YourWiFi"
#     psk="your_password"
# }
```

---

## 4. 自研 wpa_supplicant 可行性分析

### 4.1 核心需求（WPA2-PSK STA CCMP only）

```
┌─────────────────────────────────────────────┐
│  nl80211 netlink 通信层                      │
│  ├── 扫描 (NL80211_CMD_TRIGGER_SCAN)         │
│  ├── 连接 (NL80211_CMD_CONNECT)              │
│  ├── 断开 (NL80211_CMD_DISCONNECT)           │
│  └── 事件监听 (NL80211_CMD_{ASSOCIATE,       │
│       CONNECT, DISCONNECT, ...})             │
├─────────────────────────────────────────────┤
│  EAPOL 帧收发                                │
│  ├── EAPOL-Key 帧构造/解析 (802.1X type 3)    │
│  └── 4-way handshake 状态机                   │
│       Message 1: AP → STA (ANonce)           │
│       Message 2: STA → AP (SNonce + MIC)     │
│       Message 3: AP → STA (GTK + MIC)        │
│       Message 4: STA → AP (ACK)              │
├─────────────────────────────────────────────┤
│  密码算法层                                   │
│  ├── PBKDF2-HMAC-SHA1 (PSK → PMK: 4096 iter) │
│  ├── SHA1-PRF (PMK → PTK)                    │
│  ├── AES-128-CCMP (数据加解密)               │
│  ├── HMAC-SHA1 (EAPOL MIC 计算)              │
│  └── 随机数 (Nonce 生成)                      │
├─────────────────────────────────────────────┤
│  基础框架                                     │
│  ├── event loop (select/epoll)               │
│  ├── 配置文件解析                              │
│  └── ctrl interface (unix socket)            │
└─────────────────────────────────────────────┘
```

### 4.2 预估体积

| 模块 | 预估 (strip) | 说明 |
|---|---|---|
| nl80211 netlink | 20-30K | 若用 libnl，库本身 ~80K（静态链接计入） |
| EAPOL + 4-way handshake | 10-15K | 含超时/重传/PMKID 缓存 |
| PBKDF2 + SHA1 + AES-CCMP | 20-30K | 内联实现 ≈20K；用外部库会增加 |
| 基础框架 | 5-10K | event loop, config, ctrl socket |
| **不含 libnl** | **55-85K** | |
| libnl 静态链接 | ~80K | 若保留 libnl |
| **自研 + libnl** | **~140-170K** | |
| **自研 + 裸 netlink** | **~60-80K** | |

### 4.3 对比决策

| 指标 | 精简 wpa_supplicant | 自研 + libnl | 自研 + 裸 netlink |
|---|---|---|---|
| 体积 | **402K** | ~140-170K | ~60-80K |
| 开发量 | 0（已完成） | 大 (2-4 周) | 极大 (4-8 周) |
| 可靠性 | 高（成熟代码库） | 中 | 低 |
| AP 兼容性 | 极佳 (15+ 年积累) | 无 | 无 |
| 安全审计 | 已完成 | 需要 | 需要 |
| 可维护性 | 上游维护 | 自己维护 | 自己维护 |

**结论**：402K 精简版对于大部分嵌入式场景（≥ 512K 可用 flash）已足够。
仅在 flash < 256K 且 WiFi 为必需功能时，自研才有实际价值。

### 4.4 自研的隐性成本（详细）

1. **AP 兼容性 workaround**
   - 某些 AP 的 4-way handshake 时序异常
   - GTK 更新频率因厂商而异
   - WPA-to-WPA2 transition mode 下的特殊处理
   - 这些 workaround 是 wpa_supplicant 积累多年的隐性资产

2. **状态机边界 case**
   - 连接超时、握手超时、认证超时的正确处理
   - Deauth/Disassoc 帧处理
   - PMKID 缓存的写入/失效/过期逻辑
   - GTK rekey（部分 AP 每 3600s 强制更新）
   - 漫游时 PTK/GTK 的时序

3. **nl80211 接口复杂性**
   - 多属性嵌套 (NLA_NESTED) netlink 消息，解析易出错
   - 错误码映射 (nl80211 errno → 用户态错误码)
   - 内核版本差异：nl80211 自 2.6.24 到 3.x 变化很大
   - wiphy 能力协商

4. **安全审计清单**
   ```
   - PBKDF2 迭代次数必须 ≥ 4096
   - HMAC-SHA1 常数时间比较（防时序攻击）
   - Nonce 必须使用 CSPRNG (非 rand())
   - CCMP PN (Packet Number) 单调递增
   - PTK 派生中的 PRF 正确性
   - 内存清零（密钥使用后 memset(0)）
   ```

5. **维护负担**
   - nl80211 API 随内核版本增加新命令/属性
   - WPA3/SAE 如果将来需要，等于重写认证逻辑

---

## 5. cross_toolchain 目录 — 完全自包含的交叉编译工具链

### 5.1 目录结构

```
cross_toolchain/                          总计 89M
├── bin/                                  15M
│   ├── arm-buildroot-linux-uclibcgnueabi-gcc (→ gcc-4.9.3)
│   ├── arm-buildroot-linux-uclibcgnueabi-g++ (→ gcc)
│   ├── arm-buildroot-linux-uclibcgnueabi-as
│   ├── arm-buildroot-linux-uclibcgnueabi-ld
│   ├── arm-buildroot-linux-uclibcgnueabi-strip
│   ├── arm-buildroot-linux-uclibcgnueabi-nm
│   ├── arm-buildroot-linux-uclibcgnueabi-objdump
│   ├── arm-buildroot-linux-uclibcgnueabi-ranlib
│   ├── arm-buildroot-linux-uclibcgnueabi-readelf
│   ├── arm-buildroot-linux-uclibcgnueabi-size
│   ├── arm-buildroot-linux-uclibcgnueabi-strings
│   ├── arm-buildroot-linux-uclibcgnueabi-addr2line
│   ├── arm-buildroot-linux-uclibcgnueabi-objcopy
│   ├── arm-buildroot-linux-uclibcgnueabi-c++filt
│   ├── arm-buildroot-linux-uclibcgnueabi-cpp
│   ├── arm-buildroot-linux-uclibcgnueabi-elfedit
│   ├── arm-buildroot-linux-uclibcgnueabi-gcov
│   ├── arm-buildroot-linux-uclibcgnueabi-gprof
│   ├── arm-buildroot-linux-uclibcgnueabi-gcc-ar
│   ├── arm-buildroot-linux-uclibcgnueabi-gcc-nm
│   ├── arm-buildroot-linux-uclibcgnueabi-gcc-ranlib
│   └── as, ld, nm, strip, ar, cpp, ... → arm-buildroot-linux-uclibcgnueabi-*  (符号链接)
├── lib/                                  13M
│   ├── libmpfr.so.4 → libmpfr.so.4.1.3    (GCC 依赖 — 高精度浮点)
│   ├── libmpc.so.3 → libmpc.so.3.0.0      (GCC 依赖 — 复数运算)
│   ├── libgmp.so.10 → libgmp.so.10.2.0    (GCC 依赖 — 大整数)
│   └── gcc/arm-buildroot-linux-uclibcgnueabi/4.9.3/
│       ├── crtbegin.o, crtbeginS.o, crtbeginT.o   (C 运行时启动文件)
│       ├── crtend.o, crtendS.o
│       ├── libgcc.a                        (GCC 内建支持库)
│       ├── libgcov.a                       (代码覆盖率)
│       ├── include/                        (GCC 内建头文件)
│       └── install-tools/
├── libexec/                              31M
│   └── gcc/arm-buildroot-linux-uclibcgnueabi/4.9.3/
│       ├── cc1                            (C 编译器主体)
│       ├── collect2                       (链接器 wrapper)
│       ├── lto1                           (LTO 优化器)
│       ├── lto-wrapper                    (LTO 驱动)
│       ├── liblto_plugin.so               (LTO linker plugin)
│       ├── plugin/gengtype                (GCC 内部插件工具)
│       └── install-tools/fixincl          (头文件修复)
├── arm-buildroot-linux-uclibcgnueabi/    31M
│   ├── bin/
│   │   ├── as, ld, nm, strip, ar, ranlib  (目标版本 binutils)
│   │   ├── objdump, objcopy, ...
│   │   └── cc → gcc                       (符号链接)
│   ├── lib/                               (目标库目录)
│   └── sysroot/
│       └── usr/
│           ├── include/                   (目标系统头文件: linux/, netlink/, libnl3/, ...)
│           └── lib/                       (目标系统库: libc.a, libnl-3.a, libmbedtls.a, ...)
└── env.sh                                 (环境设置脚本)
```

### 5.2 RPATH 修复详情

**原理**：原始 RPATH 绝对路径 51 字符，无法直接替换为等长或更短的新路径。
使用 `chrpath` 替换为 `$ORIGIN` 相对路径，所有新路径均短于原始，因此可行。

```
原始: /root/buildroot-2015.08.1/output/host/usr/lib  (51 chars)
```

| 文件位置 | 新 RPATH | 长度 | 说明 |
|---|---|---|---|
| `bin/arm-*` | `$ORIGIN/../lib` | 15 | 从 bin/ 上 1 级再进 lib/ |
| `libexec/gcc/.../4.9.3/*` | `$ORIGIN/../../../../lib` | 27 | 从 4.9.3/ 上 4 级再进 lib/ |
| `libexec/gcc/.../4.9.3/plugin/*` | `$ORIGIN/../../../../../lib` | 31 | 从 plugin/ 上 5 级 |
| `libexec/gcc/.../install-tools/*` | `$ORIGIN/../../../../../lib` | 31 | 同上 |
| `lib/libmpfr.so.4*` | `$ORIGIN/.` | 10 | 已在 lib/ 目录中 |
| `arm-buildroot-.../bin/*` | `$ORIGIN/../../lib` | 18 | 从 target/bin/ 上 2 级 |

**$ORIGIN 路径深度验证**（以 cc1 为例）：

```
cc1 位置: libexec/gcc/arm-buildroot-linux-uclibcgnueabi/4.9.3/cc1
$ORIGIN  = libexec/gcc/arm-buildroot-linux-uclibcgnueabi/4.9.3/

../../../../ = 上 4 级:
  1: arm-buildroot-linux-uclibcgnueabi/
  2: gcc/
  3: libexec/
  4: cross_toolchain/       ← 目标目录

../../../../lib → cross_toolchain/lib  ✓
```

**首次修复错误**：最初将 cc1 级别设为 `../../../../../lib`（5 级），多上了一级，
导致解析到项目根目录而非 cross_toolchain，chroma 识别后已修正。

### 5.3 符号链接创建

GCC 驱动调用子工具时使用短名 (`as`, `ld`, `nm`, ...) 而非带 target-prefix 的全名。
在 `bin/` 下创建符号链接确保 GCC 能找到正确的交叉工具：

```bash
cd cross_toolchain/bin
for tool in as ld nm strip objcopy objdump ranlib ar cpp; do
    ln -sf arm-buildroot-linux-uclibcgnueabi-$tool $tool
done
```

### 5.4 使用方法

```bash
# 方式一：使用 env.sh
cd cross_toolchain
source env.sh
$CC -static -Os -o myapp myapp.c

# 方式二：手动设置
export PATH=/path/to/cross_toolchain/bin:$PATH
arm-buildroot-linux-uclibcgnueabi-gcc \
    --sysroot=/path/to/cross_toolchain/arm-buildroot-linux-uclibcgnueabi/sysroot \
    -static -Os -o myapp myapp.c

# 方式三：直接使用 gcc（sysroot 内置于 spec file 中，需 /root 权限修复）
export PATH=/path/to/cross_toolchain/bin:$PATH
arm-buildroot-linux-uclibcgnueabi-gcc -static -Os -o myapp myapp.c
```

### 5.5 验证结果

```bash
$ PATH=$PWD/cross_toolchain/bin:$PATH make clean strip size
$ file output/wpa_mini
# output/wpa_mini: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV),
#                  statically linked, stripped
# 441184 bytes

$ arm-buildroot-linux-uclibcgnueabi-readelf -h output/wpa_mini
# Class:     ELF32
# Machine:   ARM
```

---

## 6. 完整 Buildroot 编译流程

```bash
# === 前置修复 ===
# 1. 修复 /root 遍历权限（一次性）
sudo chmod 701 /root

# 2. 确保符号链接存在（如不存在）
sudo ln -sf /home/amamiya/repos/buildroot-2015.08.1 /root/buildroot-2015.08.1

# === 进行编译 ===
cd /home/amamiya/repos/buildroot-2015.08.1

# 首次编译（生成所有包）
make

# 仅编译 wpa_supplicant（已修改 .mk 后）
make wpa_supplicant-dirclean && make wpa_supplicant

# === 输出 ===
ls -lh output/images/rootfs.tar          # 根文件系统镜像 (6.9M)
ls -lh output/target/usr/sbin/wpa_*      # WiFi 工具 (402K + 112K)
```

### 6.1 构建时间线

```
make → core-dependencies          (基础依赖检查)
     → host-gcc-initial           (第一阶段 GCC)
     → host-binutils              (交叉 binutils)
     → host-gcc-final             (最终 GCC 4.9.3)
     → busybox                    (瑞士军刀工具集)
     → mbedtls                    (TLS 库)
     → libnl 3.2.26               (netlink 库)        [第一次断点：RPATH 问题]
     → iw 4.1                     (WiFi 调试工具)      [第二次断点：pkg-config]
     → wpa_supplicant 2.4         (WiFi 客户端)        [两次迭代精简]
     → target-finalize            (清理 + 生成镜像)
     → rootfs.tar → output/images/
```

---

## 7. Buildroot 系统概览

| 软件包 | 版本 | 用途 | 体积 (strip) |
|---|---|---|---|
| linux | 3.4.108 | 内核 | - |
| busybox | 1.23.2 | 基础命令集 | ~700K |
| wpa_supplicant | 2.4 (精简) | WiFi STA 客户端 | 402K |
| iw | 4.1 | nl80211 调试 | ~60K |
| libnl | 3.2.26 | netlink 协议库 | ~80K |
| mbedtls | 2.1.14 | 轻量 TLS | ~200K |
| dropbear | 2015.67 | SSH 服务器 | ~150K |
| zlib | 1.2.8 | 压缩库 | ~70K |

---

## 8. mbedtls 路径修复 (fix.sh)

项目内的 `fix.sh` 用于将 mbedtls 编译产物从 build 目录复制到 sysroot：

```bash
# 源: output/build/mbedtls-2.1.14/library/{libmbedtls,libmbedcrypto,libmbedx509}.a
# 目标: output/host/usr/arm-buildroot-linux-uclibcgnueabi/sysroot/usr/lib/
# 头文件: .../include/mbedtls/*.h
```

**背景**：mbedtls 使用非标准 Makefile（非 autotools/cmake），Buildroot 的
`generic-package` 无法自动完成头文件/库文件的 staging 安装，
因此需要手动脚本复制。

---

## 9. 关键调试命令速查

```bash
# RPATH 检查
readelf -d <binary> | grep RPATH
chrpath -l <binary>

# 动态链接检查
ldd <binary>                          # 查看所有依赖
ldd <binary> | grep "not found"       # 查看缺失依赖

# 库搜索路径
pkg-config --variable pc_path pkg-config
pkg-config --libs <package>

# 交叉编译器信息
arm-buildroot-linux-uclibcgnueabi-gcc -v
arm-buildroot-linux-uclibcgnueabi-gcc -dumpspecs

# ARM ELF 信息
readelf -h <binary>                   # ELF 头
readelf -d <binary>                   # 动态段
arm-buildroot-linux-uclibcgnueabi-objdump -x <binary>  # 完整信息

# 查找含特定 RPATH 的二进制
find <dir> -type f -exec sh -c 'readelf -d "$1" 2>/dev/null | grep -q RPATH && echo "$1"' _ {} \;

# 批量修复 RPATH
for f in <files>; do chrpath -r '$ORIGIN/../lib' "$f"; done
```

---

## 10. 参考链接

| 资源 | 地址 |
|---|---|
| Buildroot 文档 | http://buildroot.org/docs.html |
| wpa_supplicant | http://hostap.epitest.fi/wpa_supplicant/ |
| nl80211 头文件 | `include/uapi/linux/nl80211.h` (内核源码) |
| chrpath 手册 | https://linux.die.net/man/1/chrpath |
| GCC 内部手册 | https://gcc.gnu.org/onlinedocs/gccint/ |
| Buildroot 2015.08.1 发布 | https://buildroot.org/downloads/buildroot-2015.08.1.tar.gz |
