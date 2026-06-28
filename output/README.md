# wpa_mini 使用说明

`output` 目录是当前项目生成和交付文件的目录。

## 文件内容

- `wpa_mini`: 目标设备使用的 ARM 32-bit 静态可执行文件，已 strip。
- `wpa_mini.run`: 自解压启动包，适合放在 `/mnt/userdata` 持久分区。
- `README.md`: 本说明文件。

当前生成的 `wpa_mini` 大小为 `454768` 字节，`wpa_mini.run` 大小为 `318201` 字节。`wpa_mini` 是单一可执行文件，已经把精简 STA 连接引擎链接进程序内部，不需要额外交付 `wpa_cli` 或外部 `wpa_supplicant`。

## 功能

`wpa_mini` 提供一个 WebUI，用于控制 WiFi STA 连接：

- 中文轻量设备控制台页面。
- 扫描周围 WiFi。
- 连接 WPA/WPA2-PSK 网络。
- 连接成功后记忆 WiFi，并可在 WebUI 一键重连或删除。
- 可选锁定 BSSID。
- 调用目标系统 `/sbin/udhcpc` 获取 DHCP。
- 写入 DNS 到 `/mnt/userdata/etc_rw/resolv.conf`，默认使用阿里 `223.5.5.5` 和腾讯 `119.29.29.29`。
- 可选是否把 STA 作为默认路由，默认不接管，避免破坏厂商原有网络。

默认 WebUI 监听：

```sh
0.0.0.0:51400
```

浏览器访问：

```text
http://<设备IP>:51400/
```

## 目标设备运行

临时运行可以把 `wpa_mini` 放到目标设备 `/tmp` 后执行：

```sh
chmod +x /tmp/wpa_mini
/tmp/wpa_mini -w -i wlan0-vxd
```

持久放置推荐使用自解压包：

```sh
cp wpa_mini.run /mnt/userdata/wpa_mini.run
chmod +x /mnt/userdata/wpa_mini.run
/mnt/userdata/wpa_mini.run -w -i wlan0-vxd
```

`wpa_mini.run` 会自动解压 `wpa_mini` 到 `/tmp/wpa_mini`，设置执行权限，然后把所有参数原样传给 `/tmp/wpa_mini`。

如果无线接口不是 `wlan0-vxd`，改成实际接口：

```sh
/tmp/wpa_mini -w -i wlan0
```

指定端口：

```sh
/tmp/wpa_mini -w -i wlan0-vxd -L 51400
```

指定 DNS 文件路径：

```sh
/tmp/wpa_mini -w -i wlan0-vxd -r /mnt/userdata/etc_rw/resolv.conf
```

指定日志路径：

```sh
/tmp/wpa_mini -w -i wlan0-vxd -l /tmp/wpa_mini.log
```

## 默认参数

| 参数 | 默认值 |
| --- | --- |
| WebUI 端口 | `51400` |
| 无线接口 | `wlan0-vxd` |
| WPA 配置文件 | `/tmp/wpa_mini.conf` |
| ctrl_interface | `/tmp/wpa_mini_ctrl` |
| WPA 引擎 | 内置于 `wpa_mini` |
| WPA 引擎 pid | `/tmp/wpa_mini.pid` |
| DHCP 客户端 | `/sbin/udhcpc` |
| DHCP pid | `/tmp/wpa_mini_udhcpc.pid` |
| DHCP 脚本 | `/tmp/wpa_mini_udhcpc.sh` |
| DNS 文件 | `/mnt/userdata/etc_rw/resolv.conf` |
| 已保存 WiFi | `/mnt/userdata/etc_rw/wpa_mini_saved.conf` |
| 默认 DNS1 | `223.5.5.5` |
| 默认 DNS2 | `119.29.29.29` |
| 日志文件 | `/tmp/wpa_mini.log` |
| driver | `nl80211` |

## WebUI 操作

1. 启动程序：

```sh
/tmp/wpa_mini -w -i wlan0-vxd
```

2. 打开页面：

```text
http://<设备IP>:51400/
```

3. 点击 `扫描 WiFi` 扫描附近热点。
4. 输入 SSID 和密码，必要时填写 BSSID、DNS1/DNS2。
5. 如需让设备默认从 WiFi STA 出网，勾选 `使用 STA 作为默认路由`；默认不要勾选。
6. 点击 `连接`。
7. 连接成功后，该 WiFi 会出现在 `已保存 WiFi` 区域。
8. 后续可在 `已保存 WiFi` 中点击 `连接` 一键重连，或点击 `删除` 移除记录。
9. 需要断开时点击 `断开`。

## HTTP 接口

查看状态：

```sh
curl http://127.0.0.1:51400/status
```

扫描 WiFi：

```sh
curl http://127.0.0.1:51400/scan
```

连接 WiFi：

```sh
curl -X POST \
  -d 'ssid=MyWiFi&psk=password123&dns1=223.5.5.5&dns2=119.29.29.29' \
  http://127.0.0.1:51400/connect
```

指定 BSSID：

```sh
curl -X POST \
  -d 'ssid=MyWiFi&psk=password123&bssid=00:11:22:33:44:55' \
  http://127.0.0.1:51400/connect
```

连接隐藏 SSID：

```sh
curl -X POST \
  -d 'ssid=MyWiFi&psk=password123&hidden=1' \
  http://127.0.0.1:51400/connect
```

连接并启用默认路由：

```sh
curl -X POST \
  -d 'ssid=MyWiFi&psk=password123&route=1' \
  http://127.0.0.1:51400/connect
```

使用已保存 WiFi 连接，`idx` 是 WebUI 中保存列表的顺序，从 `0` 开始：

```sh
curl -X POST -d 'idx=0' http://127.0.0.1:51400/connect_saved
```

删除已保存 WiFi：

```sh
curl -X POST \
  -d 'ssid=MyWiFi&bssid=' \
  http://127.0.0.1:51400/forget
```

断开连接：

```sh
curl -X POST http://127.0.0.1:51400/disconnect
```

## 命令行一次性连接

不启动 WebUI，直接连接：

```sh
/tmp/wpa_mini -i wlan0-vxd -s MyWiFi -p 'password123'
```

只检查并生成配置，不启动连接：

```sh
/tmp/wpa_mini -i wlan0-vxd -s MyWiFi -p 'password123' -n
```

隐藏 SSID：

```sh
/tmp/wpa_mini -i wlan0-vxd -s MyWiFi -p 'password123' -H
```

连接后启用默认路由：

```sh
/tmp/wpa_mini -i wlan0-vxd -s MyWiFi -p 'password123' -M
```

## 生成的 WPA 配置

程序默认生成 WPA/WPA2-PSK 配置：

```conf
ctrl_interface=/tmp/wpa_mini_ctrl
ap_scan=1

network={
    ssid="MyWiFi"
    key_mgmt=WPA-PSK
    proto=WPA RSN
    pairwise=CCMP TKIP
    group=CCMP TKIP
    psk=<64-hex-psk>
}
```

普通 8-63 字节密码会在程序内部通过 PBKDF2 派生成 64 位 hex PSK 后写入 WPA 运行配置；如果输入本身已经是 64 位 hex PSK，则直接写入。运行配置和日志里不需要保存明文 WiFi 密码，WebUI 的已保存 WiFi 列表会按明文保存密码。

隐藏 SSID 会额外加入：

```conf
scan_ssid=1
```

## DHCP 和 DNS

连接完成后，程序调用：

```sh
/sbin/udhcpc -i wlan0-vxd -s /tmp/wpa_mini_udhcpc.sh -f -t 5 -T 5
```

DHCP 进程 pid 由 `wpa_mini` 写入 `/tmp/wpa_mini_udhcpc.pid`。

生成的 DHCP 脚本只操作当前 STA 接口：

- `bound/renew`: 配置 IP，按需添加默认路由，写 DNS。
- `deconfig`: 清理接口 IP，按需删除该接口默认路由。

DNS 默认写入：

```sh
/mnt/userdata/etc_rw/resolv.conf
```

默认 DNS 内容：

```conf
nameserver 223.5.5.5
nameserver 119.29.29.29
```

## 已保存 WiFi

WebUI 连接成功后会把 SSID、密码、BSSID、DNS、隐藏 SSID 和默认路由选项保存到：

```sh
/mnt/userdata/etc_rw/wpa_mini_saved.conf
```

保存文件权限为 `0600`。密码按明文保存，适合该设备的本地持久使用场景；如果设备控制权已经泄露，应视为 WiFi 密码也已经泄露。

## 日志排查

程序默认写最小运行日志：

```sh
/tmp/wpa_mini.log
```

目标设备复测时建议保留日志：

```sh
rm -f /tmp/wpa_mini.log
/tmp/wpa_mini -w -i wlan0-vxd
cat /tmp/wpa_mini.log
```

one-shot 模式如果 20 秒内没有到达 `COMPLETED`，会停止内置引擎并返回非 0，日志中会记录状态轮询结果。

默认瘦身版记录以下最小运行信息：

- HTTP `accept`、`recv`、请求路径和处理结束。
- HTTP 响应写入结果；WebUI 忽略 `SIGHUP` 和 `SIGPIPE`。
- 内置 WPA engine 的启动参数、子进程退出码。
- WPA 内部 `wpa_msg` 事件。

## 编译生成

在项目根目录执行：

```sh
PATH=$PWD/cross_toolchain/bin:$PATH make clean strip size
```

生成自解压启动包：

```sh
PATH=$PWD/cross_toolchain/bin:$PATH make run
```

诊断版会加入更多 engine wrapper 日志，体积更大：

```sh
PATH=$PWD/cross_toolchain/bin:$PATH make clean DEBUG=1 strip size
```

生成文件：

```sh
output/wpa_mini
output/wpa_mini.run
```

彻底删除整个 `output` 目录：

```sh
make distclean
```

## 运行要求

- 目标设备需要有可用无线接口，例如 `wlan0-vxd`。
- 目标设备需要存在 `/sbin/udhcpc`。
- 使用 `wpa_mini.run` 时，目标设备需要存在 `awk`，以及 `zcat`、`gunzip` 或 BusyBox `gunzip`。
- 程序通常需要 root 权限或足够的网络控制权限。
- 设备防火墙需要允许访问 `51400` 端口。

## 开机自启动

推荐把自解压包放在持久分区：

```sh
/mnt/userdata/wpa_mini.run
```

手动验证启动命令：

```sh
/mnt/userdata/wpa_mini.run -h >/dev/null 2>&1
/mnt/userdata/wpa_mini.run -w -i wlan0-vxd >/tmp/wpa_mini_boot.log 2>&1 &
```

这台设备没有标准 `/etc/init.d`、`rc.local` 或 `crond` 用户钩子。若确认允许修改只读 rootfs 的 `/etc/rc`，建议只在 `/etc/rc` 末尾加入 guarded hook：

```sh
if [ -x /mnt/userdata/wpa_mini.run ]; then
    /mnt/userdata/wpa_mini.run -h >/dev/null 2>&1
    /mnt/userdata/wpa_mini.run -w -i wlan0-vxd >/tmp/wpa_mini_boot.log 2>&1 &
fi
```

不要修改 `/etc/inittab` 为 respawn，也不要劫持厂商业务脚本。正式写入 `/etc/rc` 前应先准备备份和回滚命令。

## 安全注意

WebUI 没有登录认证，建议只在可信局域网或调试环境中开放。不要把 `51400` 端口直接暴露到不可信网络。已保存 WiFi 文件中包含明文密码，应避免让不可信用户获得设备 shell 或文件读取权限。
