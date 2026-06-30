# alice-nl80211-webui-zxic

轻量 WiFi STA WebUI。主要交付物是 `output/wpa_mini.run`，适合放到目标设备的持久分区后启动。

`wpa_mini.run` 会自解压 `wpa_mini` 到 `/tmp/wpa_mini` 并运行，默认打开 WebUI：

```text
0.0.0.0:51400
```

## 使用

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
- 开启共享时默认自动调整冲突的热点/USB 网段。
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
- 共享网络会修改目标设备的路由、NAT、`ip_forward`、`br0` 网段和 DHCP 配置。

更完整的操作和接口说明见 [output/README.md](output/README.md)。
