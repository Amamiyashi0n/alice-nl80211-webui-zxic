# wpa_mini 使用说明

`output` 目录是当前项目生成和交付文件的目录。

## 文件内容

- `wpa_mini`: 目标设备使用的 ARM 32-bit 静态可执行文件，已 strip。
- `wpa_mini.run`: 自解压启动包，适合放在 `/mnt/userdata` 持久分区。
- `README.md`: 本说明文件。

当前生成的 `wpa_mini` 大小为 `612680` 字节，`wpa_mini.run` 大小为 `359125` 字节。`wpa_mini` 是单一可执行文件，已经把精简 STA 连接引擎、WebUI 头像和赞助二维码资源链接进程序内部，不需要额外交付 `wpa_cli`、外部 `wpa_supplicant` 或图片文件。

## 功能

`wpa_mini` 提供一个 WebUI，用于控制 WiFi STA 连接：

- 中文轻量设备控制台页面，带侧边栏导航。
- 扫描周围 WiFi。
- 连接 WPA/WPA2-PSK 网络。
- 连接成功后记忆 WiFi，并可在 WebUI 一键重连或删除。
- 已保存 WiFi 可设置“在范围内自动连接”；未连接时 WebUI 会扫描附近网络，命中已保存且开启自动连接的 SSID 后自动发起连接。
- BSSID 仅在扫描结果和状态中只读显示，连接时由系统自动选择具体 AP。
- 调用目标系统 `/sbin/udhcpc` 获取 DHCP。
- 写入 DNS 到 `/mnt/userdata/etc_rw/resolv.conf`，默认使用阿里 `223.5.5.5` 和腾讯 `119.29.29.29`。
- 默认让本设备通过连接的 WiFi STA 出网。
- 可选共享网络给热点和 USB 设备：下层 `br0` 网络中的 WiFi AP 客户端和 USB/RNDIS 客户端通过 `wlan0-vxd` 出网，连接后也可单独开启或关闭；共享开关会同步写入当前已保存 WiFi，后续自动连接会按上次偏好自动恢复共享。
- 开启共享时，下层 DHCP 会直接下发当前 DNS，默认是阿里 `223.5.5.5` 和腾讯 `119.29.29.29`。
- 开启共享时只向下层客户端提供普通网关和 DNS，不强制抢占客户端已有更高优先级网络。
- 开启共享时如果检测到上游 WiFi 和热点/USB 网段冲突，默认会从 `192.168.0.0/24` 到 `192.168.255.0/24` 自动选择一个未占用网段，并继续开启共享；只有取消 `网段冲突时自动调整热点/USB 网段` 后，才会保留原网段并提示冲突。
- WebUI 可启用或关闭开机自启动。
- WebUI 拆分为控制台、网络接口、系统信息、关于四个页面，只读展示目标系统状态、全部网络接口、路由、ARP、监听端口和关键挂载分区。
- 关于页面包含项目仓库、签名、内嵌头像和独立赞助卡片；头像源文件位于 `pic/miku_compressed.jpg`，赞助二维码源文件位于 `pic/sponsor_clean.jpg`，构建时写入二进制并由 `/avatar.jpg`、`/sponsor.jpg` 返回。
- WebUI 和 HTTP 接口内置目标设备侧网络诊断，可测试 STA 网关、DNS UDP 查询、DNS TCP 连接和指定 IPv4 探测；同时包含 raw packet L2 ICMP fallback，不依赖目标系统 busybox `ping`。

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

`wpa_mini.run` 内部是 shell 头加 zip 载荷，会用目标设备的 `sed` 和 `unzip` 解压 `wpa_mini` 到 `/tmp/wpa_mini`，设置执行权限，然后把所有参数原样传给 `/tmp/wpa_mini`。

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
| 中继状态 | `/tmp/wpa_mini_relay.state` |
| 默认 DNS1 | `223.5.5.5` |
| 默认 DNS2 | `119.29.29.29` |
| 日志文件 | `/tmp/wpa_mini.log` |
| driver | `nl80211` |
| 持久启动包 | `/mnt/userdata/wpa_mini.run` |
| 持久二进制 | `/mnt/userdata/wpa_mini` |
| 自启动脚本 | `/mnt/userdata/wpa_mini_autostart.sh` |
| 系统启动钩子 | `/etc/rc` |

## WebUI 操作

1. 启动程序：

```sh
/tmp/wpa_mini -w -i wlan0-vxd
```

2. 打开页面：

```text
http://<设备IP>:51400/
```

3. 在 `控制台` 页面点击 `扫描 WiFi` 扫描附近热点。
4. 输入 SSID 和密码，必要时调整 DNS1/DNS2。BSSID 不需要填写，系统会自动选择具体 AP。
   `此 WiFi 在范围内时自动连接` 默认勾选，连接成功后会随保存记录一起保留。
5. 如需连接成功后立即让热点或 USB 网口设备也能上网，勾选 `连接后共享网络给热点和 USB 设备`。
   `网段冲突时自动调整热点/USB 网段` 默认勾选；只有明确不希望程序修改热点/USB 网段时才取消。
6. 点击 `连接`。连接成功后，本设备会自动通过这个 WiFi 访问外网。
7. 连接成功后，主面板会切换为 `当前连接`，可直接点击 `共享网络给热点和 USB 设备` 或 `关闭共享网络`；这个选择会记到当前 WiFi，后续自动连接会跟随恢复。
   如果上游网段和热点/USB 网段冲突，开启共享时默认会自动选择一个未占用本地网段并重启 `udhcpd`。
8. 连接成功后，该 WiFi 会出现在 `已保存 WiFi` 区域。
9. 后续可在 `已保存 WiFi` 中点击 `连接` 一键重连，点击 `开启自动连接` / `关闭自动连接` 调整范围内自动连接行为，或点击 `删除` 移除记录。
10. 如需开机后自动启动 WebUI，点击 `启用自启动`；程序会自动复制当前启动文件到 `/mnt/userdata` 并写入启动项。
11. 在侧边栏进入 `网络接口` 页面查看原系统接口，例如 `wan1` 到 `wan8`、`br0`、`usblan0`、`wlan0`、`wlan0-vxd`，以及路由和 ARP。
12. 在侧边栏进入 `系统信息` 页面查看主机状态、监听端口和关键挂载分区。
13. 需要断开时点击 `断开`；断开会清理 `wpa_mini` 创建的中继 NAT 规则。

## HTTP 接口

查看状态：

```sh
curl http://127.0.0.1:51400/status
```

查看只读系统快照：

```sh
curl http://127.0.0.1:51400/system
```

查看 HTML 网络接口页面：

```sh
curl http://127.0.0.1:51400/interfaces
```

查看 HTML 系统信息页面：

```sh
curl http://127.0.0.1:51400/system_page
```

从目标设备自身发起默认网络诊断：

```sh
curl http://127.0.0.1:51400/diag
```

探测指定 IPv4：

```sh
curl 'http://127.0.0.1:51400/ping?host=223.5.5.5'
```

目标系统可能会限制普通内核 ICMP/UDP socket，诊断输出中如果看到 `sendto failed errno=1`，优先查看同一目标的 `icmp-l2` 结果；`icmp-l2` 是 `wpa_mini` 自己构造 raw packet 的链路层 ping fallback。

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

连接隐藏 SSID：

```sh
curl -X POST \
  -d 'ssid=MyWiFi&psk=password123&hidden=1' \
  http://127.0.0.1:51400/connect
```

连接并共享网络给热点和 USB 设备：

```sh
curl -X POST \
  -d 'ssid=MyWiFi&psk=password123&relay=1' \
  http://127.0.0.1:51400/connect
```

已连接后开启或关闭共享网络：

```sh
curl -X POST http://127.0.0.1:51400/relay_on
curl -X POST http://127.0.0.1:51400/relay_off
```

已连接但上下游网段冲突时，调整热点/USB 网段并继续共享：

```sh
curl -X POST http://127.0.0.1:51400/relay_fix_lan
```

使用已保存 WiFi 连接，`idx` 是 WebUI 中保存列表的顺序，从 `0` 开始：

```sh
curl -X POST -d 'idx=0' http://127.0.0.1:51400/connect_saved
```

删除已保存 WiFi：

```sh
curl -X POST \
  -d 'ssid=MyWiFi' \
  http://127.0.0.1:51400/forget
```

切换已保存 WiFi 的范围内自动连接：

```sh
curl -X POST \
  -d 'ssid=MyWiFi&enabled=1' \
  http://127.0.0.1:51400/autoconnect_saved
```

断开连接：

```sh
curl -X POST http://127.0.0.1:51400/disconnect
```

启用或关闭开机自启动：

```sh
curl -X POST http://127.0.0.1:51400/autostart_on
curl -X POST http://127.0.0.1:51400/autostart_off
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

一次性连接后让本设备通过这个 WiFi 上网：

```sh
/tmp/wpa_mini -i wlan0-vxd -s MyWiFi -p 'password123' -M
```

连接后共享网络给热点和 USB 设备：

```sh
/tmp/wpa_mini -i wlan0-vxd -s MyWiFi -p 'password123' -N
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

启用 WiFi 中继/NAT 时，程序会：

- 开启 IPv4 转发：`/proc/sys/net/ipv4/ip_forward`。
- 添加 `iptables` NAT：`br0` 下层网段经 `wlan0-vxd` 做 `MASQUERADE`。
- 尝试添加 `br0` 以及 `br0` 成员接口的 FORWARD 放行规则，覆盖 `usblan0`、`wlan0` 等下层接口；若系统默认已放行，规则失败只记录日志。
- 确保 `/etc_rw/udhcpd.conf` 与当前 `br0` 网段一致，并启动 `udhcpd`，让 USB/RNDIS 和热点客户端能自动获取 IP、网关和当前 DNS。
- DHCP 只下发普通 `router` 和 `dns` 选项，不下发 classless static default route，因此不会主动覆盖 Windows 当前 WLAN 等已有网络优先级。
- 对目标系统内核无法正常从 `wlan0-vxd` 发出转发包的情况，程序会启动轻量用户态 raw packet 转发，作为 USB/RNDIS 与 STA 出口之间的补充转发路径。
- 同步 `/etc_rw/resolv.conf` 并通知 `dnsmasq` 重载，因为系统 `dnsmasq -i br0 -r /etc_rw/resolv.conf` 会服务下层客户端。
- 断开或下次重连前只删除 `wpa_mini` 自己创建的精确匹配规则，不清空系统防火墙。

## 已保存 WiFi

WebUI 连接成功后会把 SSID、密码、DNS、隐藏 SSID、共享网络选项和范围内自动连接选项保存到：

```sh
/mnt/userdata/etc_rw/wpa_mini_saved.conf
```

保存文件权限为 `0600`。密码按明文保存，适合该设备的本地持久使用场景；如果设备控制权已经泄露，应视为 WiFi 密码也已经泄露。

如果连接后在主面板单独开启或关闭共享网络，当前 SSID 的保存记录会同步更新。后续 WebUI 空闲时自动扫描并连接这个 SSID，会按保存的共享偏好自动启用共享，并在上下游网段冲突时按保存的自动调整网段偏好处理；新保存的 WiFi 默认允许自动选择未占用网段。

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

生成 `wpa_mini.run` 需要构建机存在 `python3`，用于写入 zip 载荷。
构建 `wpa_mini` 时也会使用 `python3` 把 `pic/miku_compressed.jpg` 和 `pic/sponsor_clean.jpg` 转成内嵌 C 资源。

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
- 使用 WiFi 中继/NAT 时，目标设备需要存在 `iptables`，并保留系统原有 `br0`、`dnsmasq`、`udhcpd` 服务。
- 使用 `wpa_mini.run` 时，目标设备需要存在 `sed` 和 `unzip`。当前目标设备的 BusyBox `unzip` 可用。
- 程序通常需要 root 权限或足够的网络控制权限。
- 设备防火墙需要允许访问 `51400` 端口。

## 开机自启动

WebUI 的 `启用自启动` 按钮会执行三步：

- 定位当前启动文件，并复制到 `/mnt/userdata/wpa_mini.run` 或 `/mnt/userdata/wpa_mini`。
- 写入 `/mnt/userdata/wpa_mini_autostart.sh`。
- 尝试在 `/etc/rc` 末尾写入带标记的启动钩子。

启动钩子只会包含 `# wpa_mini autostart begin` 到 `# wpa_mini autostart end` 之间的内容，关闭自启动时也只移除这段标记块。若根分区仍不可写，WebUI 会提示系统启动钩子写入失败；此时持久启动脚本可能已经写入，但真正开机自启动不会生效。

如果 WebUI 是从 `.run` 启动的，例如 `/tmp/wpa_mini.run -w`，启用自启动时会复制这个 `.run` 到 `/mnt/userdata/wpa_mini.run`。如果 WebUI 是从普通二进制启动的，则会复制当前二进制到 `/mnt/userdata/wpa_mini` 作为兜底。

开机后自启动脚本会尝试把 `/tmp` remount 为可执行，然后启动持久化后的文件：

```sh
/mnt/userdata/wpa_mini.run -w -i wlan0-vxd
# 或
/mnt/userdata/wpa_mini -w -i wlan0-vxd
```

## 安全注意

WebUI 没有登录认证，建议只在可信局域网或调试环境中开放。不要把 `51400` 端口直接暴露到不可信网络。已保存 WiFi 文件中包含明文密码，应避免让不可信用户获得设备 shell 或文件读取权限。
