# wpa_mini 使用说明

`output` 目录是当前项目生成和交付文件的目录。

## 文件内容

- `wpa_mini`: 目标设备使用的 ARM 32-bit 静态可执行文件，已 strip。
- `README.md`: 本说明文件。

当前生成的 `wpa_mini` 大小为 `448856` 字节。它是单一可执行文件，已经把精简 STA 连接引擎链接进程序内部，不需要额外交付 `wpa_cli` 或外部 `wpa_supplicant`。

## 功能

`wpa_mini` 提供一个 WebUI，用于控制 WiFi STA 连接：

- 中文浅绿主题操作页面。
- 扫描周围 WiFi。
- 连接 WPA/WPA2-PSK 网络。
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

把 `wpa_mini` 放到目标设备后执行：

```sh
chmod +x /tmp/wpa_mini
/tmp/wpa_mini -w -i wlan0-vxd
```

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

3. 点击 `Scan` 扫描附近热点。
4. 输入 SSID 和密码，必要时填写 BSSID、DNS1/DNS2。
5. 如需让设备默认从 WiFi STA 出网，勾选 `Use STA as default route`；默认不要勾选。
6. 点击 `Connect`。
7. 需要断开时点击 `Disconnect`。

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

普通 8-63 字节密码会在程序内部通过 PBKDF2 派生成 64 位 hex PSK 后写入配置；如果输入本身已经是 64 位 hex PSK，则直接写入。这样配置文件和日志里不需要保存明文 WiFi 密码。

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

诊断版会加入更多 engine wrapper 日志，体积更大：

```sh
PATH=$PWD/cross_toolchain/bin:$PATH make clean DEBUG=1 strip size
```

生成文件：

```sh
output/wpa_mini
```

彻底删除整个 `output` 目录：

```sh
make distclean
```

## 运行要求

- 目标设备需要有可用无线接口，例如 `wlan0-vxd`。
- 目标设备需要存在 `/sbin/udhcpc`。
- 程序通常需要 root 权限或足够的网络控制权限。
- 设备防火墙需要允许访问 `51400` 端口。

## 安全注意

WebUI 没有登录认证，建议只在可信局域网或调试环境中开放。不要把 `51400` 端口直接暴露到不可信网络。
