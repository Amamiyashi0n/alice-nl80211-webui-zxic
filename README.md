# alice-nl80211-webui-zxic

轻量 WiFi STA WebUI。主要交付物是 `output/wpa_mini.run`，适合放到目标设备的持久分区后启动。

`wpa_mini.run` 会自解压 `wpa_mini` 到 `/tmp/wpa_mini` 并运行，默认打开 WebUI：

```text
0.0.0.0:51400
```

## 使用

默认使用目标设备的动态运行库编译：

```sh
./make.sh
```

默认编译器是 `arm-linux-gnueabi-gcc`，并使用动态链接。如果 `.build/dynamic-lib` 还没有目标库，构建会通过 `adb -P 5038` 从在线的非模拟器设备读取 `/lib` 中的运行库；也可以预先设置 `ADB_SERIAL` 指定设备。

最终程序依赖目标设备已有的以下共享库，库本身不会打进 `.run`：

```text
/lib/ld-uClibc.so.0
/lib/libc.so.0       /lib/libdl.so.0      /lib/libm.so.0
/lib/libpthread.so.0 /lib/librt.so.0      /lib/libgcc_s.so.1
/lib/libnl-3.so.200  /lib/libnl-genl-3.so.200
```

如需构建静态对照版本：

```sh
make LINK_MODE=static output/wpa_mini.run
```

动态版本只将 `nl80211`、配置解析和 WebUI 逻辑编入主程序，系统 libc、libnl、线程和数学库由目标设备在运行时提供，以减少交付体积。

默认构建的是纯 WPA2-PSK 的 nl80211 子集：

- 只保留 STA 扫描、RSN/WPA-PSK、AES-CCMP、EAPOL 四次握手和 PBKDF2-SHA1。
- 不编译企业认证、EAP-TLS、证书校验、WPS、P2P、AP/热点和上游 Unix `ctrl_iface`。
- 引擎配置只接受 `key_mgmt=WPA-PSK`、`proto=RSN`、`pairwise=CCMP`、`group=CCMP`。
- 最终链接还裁掉 nl80211 AP/monitor/radiotap、WMM-AC、虚拟接口管理和未使用的控制/诊断回调；因此该 profile 只支持普通 STA 连接。
- WebUI 使用一个很小的本地数据报控制层提供 `PING`、`STATUS`、`SCAN`、`SCAN_RESULTS` 和 `TERMINATE`。

如需构建旧的完整引擎对照版本，可显式使用 `WPA_PROFILE=full`；它不是默认交付 profile。

推送到目标设备：

```sh
adb push output/wpa_mini.run /mnt/userdata/wpa_mini.run
```

启动：

```sh
adb shell 'chmod +x /mnt/userdata/wpa_mini.run; /mnt/userdata/wpa_mini.run -w -i wlan0-vxd'
```

如果需要从电脑本机访问 WebUI：

```sh
adb forward tcp:51400 tcp:51400
```

然后打开：

```text
http://127.0.0.1:51400/
```

如果目标设备已经有局域网 IP，也可以直接访问：

```text
http://<设备IP>:51400/
```

程序运行时还会通过目标设备现有的 `dnsmasq` 提供原厂后台别名：

```text
http://zxic-admin-webui/
```

这个名称指向原版后台，默认地址是 `192.168.0.1`，浏览器访问时使用 HTTP 80 端口。别名记录保存在 `/mnt/userdata/etc_rw/zxic-admin-webui.hosts`；nl80211 调整 `br0` 网段后，记录会自动更新到新的 LAN 地址，原厂后台内容和访问方式不变。客户端需要通过目标设备的 DHCP/DNS 获取解析；如果客户端手动指定了其他 DNS，请继续使用当前 LAN 地址访问。

## 常用参数

```sh
/mnt/userdata/wpa_mini.run -w -i wlan0-vxd -L 51400
```

| 参数 | 说明 |
| --- | --- |
| `-w` | 启动 WebUI |
| `-i <iface>` | 指定 WiFi STA 接口，默认常用 `wlan0-vxd` |
| `-L <port>` | 指定 WebUI 端口，默认 `51400` |
| `-r <path>` | 指定 DNS 文件路径 |
| `-l <path>` | 指定日志路径 |

## WebUI

页面中可以完成：

- 扫描并连接 WPA/WPA2-PSK WiFi。
- 保存连接过的 WiFi。
- 设置 WiFi 在范围内时自动连接。
- 调整 DNS，默认阿里 `223.5.5.5` 和腾讯 `119.29.29.29`。
- 让设备本身通过 STA WiFi 上网。
- 可选共享网络给热点和 USB/RNDIS 设备。
- 检测到上游与本地管理网段冲突时自动选择可用网段；继续使用会提示新的管理地址，开启共享时默认执行切换。
- 原版后台可通过 `http://zxic-admin-webui/` 访问，nl80211 调整 LAN 网段后不需要手动追踪新的管理地址。
- 启用或关闭开机自启动。

## 自启动

在 WebUI 里点击 `启用自启动` 即可。程序会定位当前启动文件，并把运行包复制到 `/mnt/userdata`，然后写入启动脚本。

推荐持久文件位置：

```text
/mnt/userdata/wpa_mini.run
```

## 注意

- 目标设备需要有 `unzip`，因为 `.run` 包会用它解压内部程序。
- `/tmp` 需要可写并可执行；如果目标系统把 `/tmp` 挂载为 `noexec`，需要先调整挂载参数。
- 保存的 WiFi 密码是明文，保存在设备本地。
- 共享网络会修改目标设备的路由、NAT、`ip_forward`、`br0` 网段和 DHCP 配置；网段切换后管理页面地址会改变。

更完整的操作和接口说明见 [output/README.md](output/README.md)。
