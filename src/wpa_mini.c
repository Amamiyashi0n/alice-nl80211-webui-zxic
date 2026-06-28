#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define DEFAULT_CONF "/tmp/wpa_mini.conf"
#define DEFAULT_CTRL "/tmp/wpa_mini_ctrl"
#define DEFAULT_DRIVER "nl80211"
#define DEFAULT_IFACE "wlan0-vxd"
#define DEFAULT_PIDFILE "/tmp/wpa_mini.pid"
#define DEFAULT_DHCP_PIDFILE "/tmp/wpa_mini_udhcpc.pid"
#define DEFAULT_DHCP_SCRIPT "/tmp/wpa_mini_udhcpc.sh"
#define DEFAULT_DNS_PATH "/mnt/userdata/etc_rw/resolv.conf"
#define DEFAULT_DNS1 "223.5.5.5"
#define DEFAULT_DNS2 "119.29.29.29"
#define DEFAULT_LOG_PATH "/tmp/wpa_mini.log"
#define DEFAULT_PORT 51400
#define DEFAULT_UDHCPC "/sbin/udhcpc"

#define HTTP_REQ_MAX 8192
#define HTTP_BODY_MAX 4096
#define CTRL_REPLY_MAX 16384
#define STATUS_REPLY_MAX 2048
#define SCAN_TEXT_MAX 16384
#define SCAN_HTML_MAX 20000
#define PAGE_BODY_MAX 32768

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

struct app_config {
	const char *iface;
	const char *conf;
	const char *ctrl_dir;
	const char *driver;
	const char *pidfile;
	const char *dhcp_pidfile;
	const char *dhcp_script;
	const char *dns_path;
	const char *log_path;
	const char *udhcpc;
	int port;
};

static char signal_log_path[PATH_MAX] = DEFAULT_LOG_PATH;
static char engine_log_path[PATH_MAX] = DEFAULT_LOG_PATH;

static int mkdir_parent(const char *path);

typedef void (*wpa_msg_cb_func)(void *ctx, int level, int global,
				const char *txt, size_t len);

#ifdef WPA_MINI_WRAP_ENGINE
struct wpa_global;
struct wpa_interface;
struct wpa_params;
struct wpa_supplicant;
struct ctrl_iface_priv;
struct wpa_config;
struct wpa_ssid;
struct netlink_config;
struct netlink_data;
struct l2_packet_data;
struct nl_msg;
struct i802_bss;
struct wpa_driver_nl80211_data;
struct rfkill_config;
struct rfkill_data;

extern void __real_wpa_msg_register_cb(wpa_msg_cb_func func);
#else
extern void wpa_msg_register_cb(wpa_msg_cb_func func) __attribute__((weak));
#endif

extern int pbkdf2_sha1(const char *passphrase, const unsigned char *ssid,
		       size_t ssid_len, int iterations, unsigned char *buf,
		       size_t buflen) __attribute__((weak));

struct runtime_status {
	int engine_running;
	int dhcp_running;
	pid_t engine_pid;
	pid_t dhcp_pid;
	char wpa_state[64];
	char ssid[96];
	char bssid[64];
	char key_mgmt[64];
	char ip[64];
	char gateway[64];
	char dns[192];
};

/*
 * Makefile links the reduced wpa_supplicant engine into this binary and
 * renames its main() symbol to wpa_engine_main. The weak fallback only keeps
 * host-side smoke builds possible.
 */
__attribute__((weak)) int wpa_engine_main(int argc, char **argv)
{
	(void)argc;
	(void)argv;
	fprintf(stderr, "internal WPA engine is not linked\n");
	return 127;
}

static int is_hex_chars(const char *s, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (!isxdigit((unsigned char)s[i]))
			return 0;
	}

	return 1;
}

static void usage(FILE *out)
{
	fprintf(out,
		"Usage:\n"
		"  wpa_mini [options]                 start WebUI on port 51400\n"
		"  wpa_mini -i IFACE -s SSID -p PSK   connect once with internal engine\n"
		"\n"
		"Options:\n"
		"  -w         force WebUI mode\n"
		"  -L PORT    WebUI listen port; default is 51400\n"
		"  -i IFACE   wireless interface; default is wlan0-vxd\n"
		"  -s SSID    WPA/WPA2-PSK SSID for one-shot mode\n"
		"  -p PSK     passphrase (8-63 bytes) or 64-hex PSK\n"
		"  -c CONF    config path; default is /tmp/wpa_mini.conf\n"
		"  -C DIR     ctrl_interface dir; default is /tmp/wpa_mini_ctrl\n"
		"  -D DRIVER  nl80211 driver name; default is nl80211\n"
		"  -P FILE    WPA engine pid file; default is /tmp/wpa_mini.pid\n"
		"  -r FILE    resolv.conf path; default is /mnt/userdata/etc_rw/resolv.conf\n"
		"  -l FILE    log path; default is /tmp/wpa_mini.log\n"
		"  -u PATH    udhcpc path; default is /sbin/udhcpc\n"
		"  -H         set scan_ssid=1 for hidden SSIDs in one-shot mode\n"
		"  -M         add default route through STA after DHCP in one-shot mode\n"
		"  -F         keep foreground parent alive in one-shot mode\n"
		"  -n         write/check config only in one-shot mode\n"
		"  -h         show this help\n");
}

static long long now_ms(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static void log_msg(const struct app_config *cfg, const char *fmt, ...)
{
	FILE *fp;
	va_list ap;
	long long ms;

	if (!cfg || !cfg->log_path || !*cfg->log_path)
		return;

	if (mkdir_parent(cfg->log_path) < 0)
		return;
	fp = fopen(cfg->log_path, "a");
	if (!fp)
		return;

	ms = now_ms();
	fprintf(fp, "[%lld.%03lld] pid=%ld ",
		ms / 1000, ms % 1000, (long)getpid());
	va_start(ap, fmt);
	vfprintf(fp, fmt, ap);
	va_end(ap);
	fputc('\n', fp);
	fclose(fp);
}

static void set_engine_log_path(const char *path)
{
	if (!path || !*path)
		return;
	snprintf(engine_log_path, sizeof(engine_log_path), "%s", path);
}

static void engine_log_msg(const char *fmt, ...)
{
	FILE *fp;
	va_list ap;
	long long ms;

	if (mkdir_parent(engine_log_path) < 0)
		return;
	fp = fopen(engine_log_path, "a");
	if (!fp)
		return;

	ms = now_ms();
	fprintf(fp, "[%lld.%03lld] pid=%ld ",
		ms / 1000, ms % 1000, (long)getpid());
	va_start(ap, fmt);
	vfprintf(fp, fmt, ap);
	va_end(ap);
	fputc('\n', fp);
	fclose(fp);
}

static void engine_wpa_msg_cb(void *ctx, int level, int global,
			      const char *txt, size_t len)
{
	FILE *fp;
	long long ms;
	size_t capped = 0;

	(void)ctx;
	if (!txt)
		return;
	while (capped < 4096 && txt[capped])
		capped++;
	if (len > capped)
		len = capped;
	if (mkdir_parent(engine_log_path) < 0)
		return;
	fp = fopen(engine_log_path, "a");
	if (!fp)
		return;

	ms = now_ms();
	fprintf(fp, "[%lld.%03lld] pid=%ld engine msg level=%d global=%d ",
		ms / 1000, ms % 1000, (long)getpid(), level, global);
	fwrite(txt, 1, len, fp);
	fputc('\n', fp);
	fclose(fp);
}

#ifdef WPA_MINI_WRAP_ENGINE
static wpa_msg_cb_func engine_downstream_wpa_msg_cb;

static void engine_wpa_msg_mux_cb(void *ctx, int level, int global,
				  const char *txt, size_t len)
{
	engine_wpa_msg_cb(ctx, level, global, txt, len);
	if (engine_downstream_wpa_msg_cb &&
	    engine_downstream_wpa_msg_cb != engine_wpa_msg_mux_cb)
		engine_downstream_wpa_msg_cb(ctx, level, global, txt, len);
}

void __wrap_wpa_msg_register_cb(wpa_msg_cb_func func)
{
	engine_downstream_wpa_msg_cb = func;
	__real_wpa_msg_register_cb(engine_wpa_msg_mux_cb);
	engine_log_msg("wrap wpa_msg_register_cb downstream=%p", (void *)func);
}

extern struct wpa_global *__real_wpa_supplicant_init(struct wpa_params *params);
extern struct wpa_supplicant *__real_wpa_supplicant_add_iface(
	struct wpa_global *global, struct wpa_interface *iface,
	struct wpa_supplicant *parent);
extern struct wpa_config *__real_wpa_config_read(const char *name,
						 struct wpa_config *cfgp);
extern int __real_wpa_config_set(struct wpa_ssid *ssid, const char *var,
				 const char *value, int line);
extern int __real_wpa_config_process_global(struct wpa_config *config,
					    char *pos, int line);
extern int __real_wpa_supplicant_driver_init(struct wpa_supplicant *wpa_s);
extern int __real_wpa_supplicant_update_mac_addr(struct wpa_supplicant *wpa_s);
extern int __real_wpa_supplicant_init_wpa(struct wpa_supplicant *wpa_s);
extern int __real_wpa_supplicant_init_eapol(struct wpa_supplicant *wpa_s);
extern struct ctrl_iface_priv *__real_wpa_supplicant_ctrl_iface_init(
	struct wpa_supplicant *wpa_s);
extern int __real_wpa_bss_init(struct wpa_supplicant *wpa_s);
extern int __real_wpa_supplicant_run(struct wpa_global *global);
extern struct netlink_data *__real_netlink_init(struct netlink_config *cfg);
extern struct l2_packet_data *__real_l2_packet_init(
	const char *ifname, const unsigned char *own_addr,
	unsigned short protocol,
	void (*rx_callback)(void *ctx, const unsigned char *src_addr,
			    const unsigned char *buf, size_t len),
	void *rx_callback_ctx, int l2_hdr);
extern struct l2_packet_data *__real_l2_packet_init_bridge(
	const char *br_ifname, const char *ifname,
	const unsigned char *own_addr, unsigned short protocol,
	void (*rx_callback)(void *ctx, const unsigned char *src_addr,
			    const unsigned char *buf, size_t len),
	void *rx_callback_ctx, int l2_hdr);
extern int __real_wpa_driver_nl80211_capa(struct wpa_driver_nl80211_data *drv);
extern const unsigned char *__real_wpa_driver_nl80211_get_macaddr(void *priv);
extern int __real_wpa_driver_nl80211_set_mode(struct i802_bss *bss,
					      int nlmode);
extern int __real_nl80211_get_wiphy_index(struct i802_bss *bss);
extern int __real_send_and_recv_msgs(
	struct wpa_driver_nl80211_data *drv, struct nl_msg *msg,
	int (*valid_handler)(struct nl_msg *, void *), void *valid_data);
extern struct rfkill_data *__real_rfkill_init(struct rfkill_config *cfg);
extern int __real_linux_iface_up(int sock, const char *ifname);
extern int __real_linux_set_iface_flags(int sock, const char *ifname,
					int dev_up);
extern int __real_linux_get_ifhwaddr(int sock, const char *ifname,
				     unsigned char *addr);
extern unsigned int __real_if_nametoindex(const char *ifname);
extern int __real_genl_ctrl_resolve(void *sk, const char *name);

struct wpa_global *__wrap_wpa_supplicant_init(struct wpa_params *params)
{
	struct wpa_global *ret;

	engine_log_msg("wrap wpa_supplicant_init enter");
	ret = __real_wpa_supplicant_init(params);
	engine_log_msg("wrap wpa_supplicant_init ret=%p", (void *)ret);
	return ret;
}

struct wpa_supplicant *__wrap_wpa_supplicant_add_iface(
	struct wpa_global *global, struct wpa_interface *iface,
	struct wpa_supplicant *parent)
{
	struct wpa_supplicant *ret;

	engine_log_msg("wrap wpa_supplicant_add_iface enter global=%p iface=%p",
		       (void *)global, (void *)iface);
	ret = __real_wpa_supplicant_add_iface(global, iface, parent);
	engine_log_msg("wrap wpa_supplicant_add_iface ret=%p", (void *)ret);
	return ret;
}

static void log_config_line_summary(int line_no, const char *line)
{
	char clean[256];
	const char *p;
	size_t len;
	int psk_hex = 0;
	int psk_quoted = 0;

	if (!line)
		return;

	len = strcspn(line, "\r\n");
	if (len >= sizeof(clean))
		len = sizeof(clean) - 1;
	memcpy(clean, line, len);
	clean[len] = '\0';

	p = clean;
	while (*p == ' ' || *p == '\t')
		p++;

	if (strncmp(p, "psk=", 4) == 0) {
		const char *v = p + 4;
		size_t vlen = strlen(v);

		if (vlen == 64 && is_hex_chars(v, vlen))
			psk_hex = 1;
		if (*v == '"')
			psk_quoted = 1;
		engine_log_msg("config line %d: psk=<redacted len=%lu hex=%d quoted=%d>",
			       line_no, (unsigned long)vlen, psk_hex,
			       psk_quoted);
		return;
	}

	engine_log_msg("config line %d: %s", line_no, clean);
}

static void log_config_file_summary(const char *path)
{
	FILE *fp;
	char line[512];
	int line_no = 0;

	if (!path || !*path) {
		engine_log_msg("config summary skipped: empty path");
		return;
	}

	fp = fopen(path, "r");
	if (!fp) {
		engine_log_msg("config summary open failed path=%s errno=%d",
			       path, errno);
		return;
	}

	while (fgets(line, sizeof(line), fp)) {
		line_no++;
		if (line_no > 80) {
			engine_log_msg("config summary truncated after 80 lines");
			break;
		}
		log_config_line_summary(line_no, line);
	}

	if (ferror(fp))
		engine_log_msg("config summary read error errno=%d", errno);
	fclose(fp);
}

struct wpa_config *__wrap_wpa_config_read(const char *name,
					  struct wpa_config *cfgp)
{
	struct wpa_config *ret;

	engine_log_msg("wrap wpa_config_read enter name=%s cfgp=%p",
		       name ? name : "", (void *)cfgp);
	log_config_file_summary(name);
	ret = __real_wpa_config_read(name, cfgp);
	engine_log_msg("wrap wpa_config_read ret=%p errno=%d", (void *)ret,
		       errno);
	return ret;
}

int __wrap_wpa_config_set(struct wpa_ssid *ssid, const char *var,
			  const char *value, int line)
{
	int ret;

	if (var && value && strcmp(var, "psk") == 0) {
		size_t len = strlen(value);
		engine_log_msg(
			"wrap wpa_config_set line=%d var=psk value=<redacted len=%lu hex=%d quoted=%d>",
			line, (unsigned long)len,
			len == 64 && is_hex_chars(value, len),
			value[0] == '"');
	} else {
		engine_log_msg("wrap wpa_config_set line=%d var=%s value=%s",
			       line, var ? var : "", value ? value : "");
	}

	ret = __real_wpa_config_set(ssid, var, value, line);
	engine_log_msg("wrap wpa_config_set line=%d var=%s ret=%d errno=%d",
		       line, var ? var : "", ret, errno);
	return ret;
}

int __wrap_wpa_config_process_global(struct wpa_config *config, char *pos,
				     int line)
{
	int ret;

	engine_log_msg("wrap wpa_config_process_global line=%d pos=%s",
		       line, pos ? pos : "");
	ret = __real_wpa_config_process_global(config, pos, line);
	engine_log_msg(
		"wrap wpa_config_process_global line=%d ret=%d errno=%d",
		line, ret, errno);
	return ret;
}

int __wrap_wpa_supplicant_driver_init(struct wpa_supplicant *wpa_s)
{
	int ret;

	engine_log_msg("wrap wpa_supplicant_driver_init enter wpa_s=%p",
		       (void *)wpa_s);
	ret = __real_wpa_supplicant_driver_init(wpa_s);
	engine_log_msg("wrap wpa_supplicant_driver_init ret=%d errno=%d",
		       ret, errno);
	return ret;
}

int __wrap_wpa_supplicant_update_mac_addr(struct wpa_supplicant *wpa_s)
{
	int ret;

	engine_log_msg("wrap wpa_supplicant_update_mac_addr enter wpa_s=%p",
		       (void *)wpa_s);
	ret = __real_wpa_supplicant_update_mac_addr(wpa_s);
	engine_log_msg("wrap wpa_supplicant_update_mac_addr ret=%d errno=%d",
		       ret, errno);
	return ret;
}

int __wrap_wpa_supplicant_init_wpa(struct wpa_supplicant *wpa_s)
{
	int ret;

	engine_log_msg("wrap wpa_supplicant_init_wpa enter wpa_s=%p",
		       (void *)wpa_s);
	ret = __real_wpa_supplicant_init_wpa(wpa_s);
	engine_log_msg("wrap wpa_supplicant_init_wpa ret=%d errno=%d",
		       ret, errno);
	return ret;
}

int __wrap_wpa_supplicant_init_eapol(struct wpa_supplicant *wpa_s)
{
	int ret;

	engine_log_msg("wrap wpa_supplicant_init_eapol enter wpa_s=%p",
		       (void *)wpa_s);
	ret = __real_wpa_supplicant_init_eapol(wpa_s);
	engine_log_msg("wrap wpa_supplicant_init_eapol ret=%d errno=%d",
		       ret, errno);
	return ret;
}

struct ctrl_iface_priv *__wrap_wpa_supplicant_ctrl_iface_init(
	struct wpa_supplicant *wpa_s)
{
	struct ctrl_iface_priv *ret;

	engine_log_msg("wrap wpa_supplicant_ctrl_iface_init enter wpa_s=%p",
		       (void *)wpa_s);
	ret = __real_wpa_supplicant_ctrl_iface_init(wpa_s);
	engine_log_msg("wrap wpa_supplicant_ctrl_iface_init ret=%p errno=%d",
		       (void *)ret, errno);
	return ret;
}

int __wrap_wpa_bss_init(struct wpa_supplicant *wpa_s)
{
	int ret;

	engine_log_msg("wrap wpa_bss_init enter wpa_s=%p", (void *)wpa_s);
	ret = __real_wpa_bss_init(wpa_s);
	engine_log_msg("wrap wpa_bss_init ret=%d errno=%d", ret, errno);
	return ret;
}

int __wrap_wpa_supplicant_run(struct wpa_global *global)
{
	int ret;

	engine_log_msg("wrap wpa_supplicant_run enter global=%p",
		       (void *)global);
	ret = __real_wpa_supplicant_run(global);
	engine_log_msg("wrap wpa_supplicant_run ret=%d errno=%d", ret, errno);
	return ret;
}

struct netlink_data *__wrap_netlink_init(struct netlink_config *cfg)
{
	struct netlink_data *ret;

	engine_log_msg("wrap netlink_init enter cfg=%p", (void *)cfg);
	ret = __real_netlink_init(cfg);
	engine_log_msg("wrap netlink_init ret=%p errno=%d", (void *)ret,
		       errno);
	return ret;
}

struct l2_packet_data *__wrap_l2_packet_init(
	const char *ifname, const unsigned char *own_addr,
	unsigned short protocol,
	void (*rx_callback)(void *ctx, const unsigned char *src_addr,
			    const unsigned char *buf, size_t len),
	void *rx_callback_ctx, int l2_hdr)
{
	struct l2_packet_data *ret;

	(void)own_addr;
	(void)rx_callback;
	(void)rx_callback_ctx;
	engine_log_msg("wrap l2_packet_init enter ifname=%s proto=0x%x hdr=%d",
		       ifname ? ifname : "", protocol, l2_hdr);
	ret = __real_l2_packet_init(ifname, own_addr, protocol, rx_callback,
				    rx_callback_ctx, l2_hdr);
	engine_log_msg("wrap l2_packet_init ret=%p errno=%d", (void *)ret,
		       errno);
	return ret;
}

struct l2_packet_data *__wrap_l2_packet_init_bridge(
	const char *br_ifname, const char *ifname,
	const unsigned char *own_addr, unsigned short protocol,
	void (*rx_callback)(void *ctx, const unsigned char *src_addr,
			    const unsigned char *buf, size_t len),
	void *rx_callback_ctx, int l2_hdr)
{
	struct l2_packet_data *ret;

	(void)own_addr;
	(void)rx_callback;
	(void)rx_callback_ctx;
	engine_log_msg(
		"wrap l2_packet_init_bridge enter br=%s ifname=%s proto=0x%x hdr=%d",
		br_ifname ? br_ifname : "", ifname ? ifname : "", protocol,
		l2_hdr);
	ret = __real_l2_packet_init_bridge(br_ifname, ifname, own_addr,
					   protocol, rx_callback,
					   rx_callback_ctx, l2_hdr);
	engine_log_msg("wrap l2_packet_init_bridge ret=%p errno=%d",
		       (void *)ret, errno);
	return ret;
}

int __wrap_wpa_driver_nl80211_capa(struct wpa_driver_nl80211_data *drv)
{
	int ret;

	engine_log_msg("wrap wpa_driver_nl80211_capa enter drv=%p",
		       (void *)drv);
	ret = __real_wpa_driver_nl80211_capa(drv);
	engine_log_msg("wrap wpa_driver_nl80211_capa ret=%d errno=%d",
		       ret, errno);
	return ret;
}

const unsigned char *__wrap_wpa_driver_nl80211_get_macaddr(void *priv)
{
	const unsigned char *ret;

	engine_log_msg("wrap wpa_driver_nl80211_get_macaddr enter priv=%p",
		       priv);
	ret = __real_wpa_driver_nl80211_get_macaddr(priv);
	if (ret) {
		engine_log_msg(
			"wrap wpa_driver_nl80211_get_macaddr ret=%02x:%02x:%02x:%02x:%02x:%02x",
			ret[0], ret[1], ret[2], ret[3], ret[4], ret[5]);
	} else {
		engine_log_msg("wrap wpa_driver_nl80211_get_macaddr ret=NULL errno=%d",
			       errno);
	}
	return ret;
}

int __wrap_wpa_driver_nl80211_set_mode(struct i802_bss *bss, int nlmode)
{
	int ret;

	engine_log_msg("wrap wpa_driver_nl80211_set_mode enter bss=%p mode=%d",
		       (void *)bss, nlmode);
	ret = __real_wpa_driver_nl80211_set_mode(bss, nlmode);
	engine_log_msg("wrap wpa_driver_nl80211_set_mode ret=%d errno=%d",
		       ret, errno);
	return ret;
}

int __wrap_nl80211_get_wiphy_index(struct i802_bss *bss)
{
	int ret;

	engine_log_msg("wrap nl80211_get_wiphy_index enter bss=%p",
		       (void *)bss);
	ret = __real_nl80211_get_wiphy_index(bss);
	engine_log_msg("wrap nl80211_get_wiphy_index ret=%d errno=%d",
		       ret, errno);
	return ret;
}

int __wrap_send_and_recv_msgs(
	struct wpa_driver_nl80211_data *drv, struct nl_msg *msg,
	int (*valid_handler)(struct nl_msg *, void *), void *valid_data)
{
	int ret;

	(void)valid_handler;
	(void)valid_data;
	engine_log_msg("wrap send_and_recv_msgs enter drv=%p msg=%p",
		       (void *)drv, (void *)msg);
	ret = __real_send_and_recv_msgs(drv, msg, valid_handler, valid_data);
	engine_log_msg("wrap send_and_recv_msgs ret=%d errno=%d",
		       ret, errno);
	return ret;
}

struct rfkill_data *__wrap_rfkill_init(struct rfkill_config *cfg)
{
	struct rfkill_data *ret;

	engine_log_msg("wrap rfkill_init enter cfg=%p", (void *)cfg);
	ret = __real_rfkill_init(cfg);
	engine_log_msg("wrap rfkill_init ret=%p errno=%d", (void *)ret,
		       errno);
	return ret;
}

int __wrap_linux_iface_up(int sock, const char *ifname)
{
	int ret;

	engine_log_msg("wrap linux_iface_up enter sock=%d ifname=%s", sock,
		       ifname ? ifname : "");
	ret = __real_linux_iface_up(sock, ifname);
	engine_log_msg("wrap linux_iface_up ret=%d errno=%d", ret, errno);
	return ret;
}

int __wrap_linux_set_iface_flags(int sock, const char *ifname, int dev_up)
{
	int ret;

	engine_log_msg("wrap linux_set_iface_flags enter sock=%d ifname=%s up=%d",
		       sock, ifname ? ifname : "", dev_up);
	ret = __real_linux_set_iface_flags(sock, ifname, dev_up);
	engine_log_msg("wrap linux_set_iface_flags ret=%d errno=%d", ret, errno);
	return ret;
}

int __wrap_linux_get_ifhwaddr(int sock, const char *ifname,
			      unsigned char *addr)
{
	int ret;

	engine_log_msg("wrap linux_get_ifhwaddr enter sock=%d ifname=%s",
		       sock, ifname ? ifname : "");
	ret = __real_linux_get_ifhwaddr(sock, ifname, addr);
	if (ret == 0 && addr) {
		engine_log_msg(
			"wrap linux_get_ifhwaddr ret=0 addr=%02x:%02x:%02x:%02x:%02x:%02x",
			addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	} else {
		engine_log_msg("wrap linux_get_ifhwaddr ret=%d errno=%d",
			       ret, errno);
	}
	return ret;
}

unsigned int __wrap_if_nametoindex(const char *ifname)
{
	unsigned int ret;

	ret = __real_if_nametoindex(ifname);
	engine_log_msg("wrap if_nametoindex ifname=%s ret=%u errno=%d",
		       ifname ? ifname : "", ret, errno);
	return ret;
}

int __wrap_genl_ctrl_resolve(void *sk, const char *name)
{
	int ret;

	engine_log_msg("wrap genl_ctrl_resolve enter sk=%p name=%s", sk,
		       name ? name : "");
	ret = __real_genl_ctrl_resolve(sk, name);
	engine_log_msg("wrap genl_ctrl_resolve ret=%d errno=%d", ret, errno);
	return ret;
}
#endif

static void register_engine_wpa_logging(void)
{
#ifdef WPA_MINI_WRAP_ENGINE
	__real_wpa_msg_register_cb(engine_wpa_msg_mux_cb);
	engine_log_msg("engine msg callback registered with mux");
#else
	if (wpa_msg_register_cb) {
		wpa_msg_register_cb(engine_wpa_msg_cb);
		engine_log_msg("engine msg callback registered");
	} else {
		engine_log_msg("engine msg callback unavailable");
	}
#endif
}

static void fatal_signal_handler(int sig)
{
	int fd;
	char buf[] = "fatal signal 00\n";

	fd = open(signal_log_path, O_WRONLY | O_CREAT | O_APPEND, 0600);
	if (fd >= 0) {
		buf[13] = (char)('0' + (sig / 10) % 10);
		buf[14] = (char)('0' + sig % 10);
		if (write(fd, buf, sizeof(buf) - 1) < 0) {
		}
		close(fd);
	}

	_exit(128 + sig);
}

static void install_signal_handlers(const struct app_config *cfg)
{
	struct sigaction sa;

	if (cfg && cfg->log_path) {
		snprintf(signal_log_path, sizeof(signal_log_path), "%s",
			 cfg->log_path);
		set_engine_log_path(cfg->log_path);
	}

	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = fatal_signal_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESETHAND;
	sigaction(SIGSEGV, &sa, NULL);
	sigaction(SIGBUS, &sa, NULL);
	sigaction(SIGILL, &sa, NULL);
	sigaction(SIGABRT, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
}

static void buf_append(char *buf, size_t bufsz, const char *fmt, ...)
{
	va_list ap;
	size_t used;
	int n;

	if (!bufsz)
		return;
	used = strlen(buf);
	if (used >= bufsz - 1)
		return;
	va_start(ap, fmt);
	n = vsnprintf(buf + used, bufsz - used, fmt, ap);
	va_end(ap);
	if (n < 0)
		buf[used] = '\0';
}

static int mkdir_p(const char *path)
{
	char tmp[PATH_MAX];
	size_t len;
	char *p;

	if (!path || !*path)
		return 0;

	len = strlen(path);
	if (len >= sizeof(tmp)) {
		errno = ENAMETOOLONG;
		return -1;
	}

	memcpy(tmp, path, len + 1);
	while (len > 1 && tmp[len - 1] == '/')
		tmp[--len] = '\0';

	for (p = tmp + 1; *p; p++) {
		if (*p != '/')
			continue;
		*p = '\0';
		if (mkdir(tmp, 0755) < 0 && errno != EEXIST)
			return -1;
		*p = '/';
	}

	if (mkdir(tmp, 0755) < 0 && errno != EEXIST)
		return -1;

	return 0;
}

static int mkdir_parent(const char *path)
{
	char tmp[PATH_MAX];
	char *slash;
	size_t len;

	len = strlen(path);
	if (len >= sizeof(tmp)) {
		errno = ENAMETOOLONG;
		return -1;
	}

	memcpy(tmp, path, len + 1);
	slash = strrchr(tmp, '/');
	if (!slash || slash == tmp)
		return 0;

	*slash = '\0';
	return mkdir_p(tmp);
}

static int is_hex_psk(const char *s)
{
	if (strlen(s) != 64)
		return 0;

	return is_hex_chars(s, 64);
}

static int valid_psk(const char *s)
{
	size_t len = strlen(s);

	if (is_hex_psk(s))
		return 1;

	return len >= 8 && len <= 63;
}

static int valid_ipv4_or_empty(const char *s)
{
	struct in_addr a;

	if (!s || !*s)
		return 1;
	return inet_pton(AF_INET, s, &a) == 1;
}

static void write_quoted(FILE *fp, const char *s)
{
	const unsigned char *p = (const unsigned char *)s;

	fputc('"', fp);
	for (; *p; p++) {
		if (*p == '\\' || *p == '"') {
			fputc('\\', fp);
			fputc(*p, fp);
		} else if (*p >= 32 && *p < 127) {
			fputc(*p, fp);
		} else {
			fprintf(fp, "\\x%02x", *p);
		}
	}
	fputc('"', fp);
}

static int derive_psk_hex(const char *ssid, const char *passphrase,
			  char *out, size_t outsz)
{
	static const char hex[] = "0123456789abcdef";
	unsigned char key[32];
	size_t i;

	if (outsz < 65) {
		errno = ENOSPC;
		return -1;
	}

	if (!pbkdf2_sha1) {
		errno = ENOSYS;
		return -1;
	}

	if (pbkdf2_sha1(passphrase, (const unsigned char *)ssid,
			strlen(ssid), 4096, key, sizeof(key)) < 0)
		return -1;

	for (i = 0; i < sizeof(key); i++) {
		out[i * 2] = hex[key[i] >> 4];
		out[i * 2 + 1] = hex[key[i] & 0x0f];
	}
	out[64] = '\0';
	return 0;
}

static void write_psk_value(FILE *fp, const char *ssid, const char *psk)
{
	char hex_psk[65];

	if (is_hex_psk(psk)) {
		fprintf(fp, "%s", psk);
		return;
	}

	if (derive_psk_hex(ssid, psk, hex_psk, sizeof(hex_psk)) == 0) {
		fprintf(fp, "%s", hex_psk);
		return;
	}

	write_quoted(fp, psk);
}

static int write_base_config(const char *path, const char *ctrl_dir)
{
	int fd;
	FILE *fp;

	if (mkdir_parent(path) < 0) {
		perror("mkdir config parent");
		return -1;
	}

	if (mkdir_p(ctrl_dir) < 0) {
		perror("mkdir ctrl_interface");
		return -1;
	}

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) {
		perror("open config");
		return -1;
	}

	fp = fdopen(fd, "w");
	if (!fp) {
		perror("fdopen config");
		close(fd);
		return -1;
	}

	fprintf(fp, "ctrl_interface=%s\n", ctrl_dir);
	fprintf(fp, "ap_scan=1\n");

	if (fclose(fp) != 0) {
		perror("write config");
		return -1;
	}

	if (chmod(path, 0600) < 0) {
		perror("chmod config");
		return -1;
	}

	return 0;
}

static int valid_bssid_or_empty(const char *s)
{
	int i;

	if (!s || !*s)
		return 1;
	if (strlen(s) != 17)
		return 0;

	for (i = 0; i < 17; i++) {
		if ((i + 1) % 3 == 0) {
			if (s[i] != ':')
				return 0;
		} else if (!isxdigit((unsigned char)s[i])) {
			return 0;
		}
	}

	return 1;
}

static int write_config(const char *path, const char *ctrl_dir,
			const char *ssid, const char *psk,
			const char *bssid, int hidden)
{
	int fd;
	FILE *fp;

	if (strlen(ssid) == 0 || strlen(ssid) > 32) {
		fprintf(stderr, "SSID must be 1-32 bytes\n");
		return -1;
	}

	if (!valid_psk(psk)) {
		fprintf(stderr, "PSK must be 8-63 bytes or a 64-hex key\n");
		return -1;
	}

	if (mkdir_parent(path) < 0) {
		perror("mkdir config parent");
		return -1;
	}

	if (mkdir_p(ctrl_dir) < 0) {
		perror("mkdir ctrl_interface");
		return -1;
	}

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) {
		perror("open config");
		return -1;
	}

	fp = fdopen(fd, "w");
	if (!fp) {
		perror("fdopen config");
		close(fd);
		return -1;
	}

	fprintf(fp, "ctrl_interface=%s\n", ctrl_dir);
	fprintf(fp, "ap_scan=1\n\n");
	fprintf(fp, "network={\n");
	fprintf(fp, "\tssid=");
	write_quoted(fp, ssid);
	fprintf(fp, "\n");
	if (bssid && *bssid)
		fprintf(fp, "\tbssid=%s\n", bssid);
	if (hidden)
		fprintf(fp, "\tscan_ssid=1\n");
	fprintf(fp, "\tkey_mgmt=WPA-PSK\n");
	fprintf(fp, "\tproto=WPA RSN\n");
	fprintf(fp, "\tpairwise=CCMP TKIP\n");
	fprintf(fp, "\tgroup=CCMP TKIP\n");
	fprintf(fp, "\tpsk=");
	write_psk_value(fp, ssid, psk);
	fprintf(fp, "\n}\n");

	if (fclose(fp) != 0) {
		perror("write config");
		return -1;
	}

	if (chmod(path, 0600) < 0) {
		perror("chmod config");
		return -1;
	}

	return 0;
}

static unsigned long long process_start_time(pid_t pid)
{
	char path[64];
	char line[512];
	char *p;
	int field;
	FILE *fp;

	snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
	fp = fopen(path, "r");
	if (!fp)
		return 0;
	if (!fgets(line, sizeof(line), fp)) {
		fclose(fp);
		return 0;
	}
	fclose(fp);

	p = strrchr(line, ')');
	if (!p)
		return 0;
	p += 2;

	for (field = 3; field <= 22; field++) {
		while (*p == ' ')
			p++;
		if (!*p)
			return 0;
		if (field == 22)
			return strtoull(p, NULL, 10);
		while (*p && *p != ' ')
			p++;
	}

	return 0;
}

static int read_pid(const char *pidfile, pid_t *pid)
{
	FILE *fp;
	long value;
	unsigned long long start = 0;
	unsigned long long current;
	int fields;

	fp = fopen(pidfile, "r");
	if (!fp)
		return -1;
	fields = fscanf(fp, "%ld %llu", &value, &start);
	if (fields != 2 || value <= 0 || start == 0) {
		fclose(fp);
		return -1;
	}
	fclose(fp);
	current = process_start_time((pid_t)value);
	if (current == 0 || current != start)
		return -1;
	*pid = (pid_t)value;
	return 0;
}

static int write_pid(const char *pidfile, pid_t pid)
{
	FILE *fp;
	unsigned long long start;

	if (mkdir_parent(pidfile) < 0)
		return -1;

	start = process_start_time(pid);
	if (start == 0)
		return -1;

	fp = fopen(pidfile, "w");
	if (!fp)
		return -1;
	fprintf(fp, "%ld %llu\n", (long)pid, start);
	if (fclose(fp) != 0)
		return -1;
	return 0;
}

static int process_is_zombie(pid_t pid)
{
	char path[64];
	char line[512];
	char *p;
	FILE *fp;
	int n;

	n = snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
	if (n < 0 || (size_t)n >= sizeof(path))
		return 0;
	fp = fopen(path, "r");
	if (!fp)
		return 0;
	if (!fgets(line, sizeof(line), fp)) {
		fclose(fp);
		return 0;
	}
	fclose(fp);

	p = strrchr(line, ')');
	if (!p || p[1] != ' ' || !p[2])
		return 0;
	return p[2] == 'Z';
}

static int process_running(pid_t pid)
{
	if (pid <= 0)
		return 0;
	if (kill(pid, 0) == 0)
		return !process_is_zombie(pid);
	if (errno == EPERM && !process_is_zombie(pid))
		return 1;
	return 0;
}

static int ctrl_socket_path(const struct app_config *cfg,
			    char *out, size_t outsz)
{
	int n;

	n = snprintf(out, outsz, "%s/%s", cfg->ctrl_dir, cfg->iface);
	if (n < 0 || (size_t)n >= outsz) {
		errno = ENAMETOOLONG;
		return -1;
	}
	return 0;
}

static int wpa_ctrl_request(const struct app_config *cfg, const char *cmd,
			    char *reply, size_t *reply_len, int timeout_ms)
{
	int fd = -1;
	struct sockaddr_un local_addr;
	struct sockaddr_un dest_addr;
	char dest[sizeof(dest_addr.sun_path)];
	char local[sizeof(local_addr.sun_path)];
	struct timeval tv;
	fd_set rfds;
	ssize_t n;
	int ret = -1;
	int seq;
	static int counter;
	size_t cap;

	if (!reply || !reply_len || !*reply_len) {
		errno = EINVAL;
		return -1;
	}
	cap = *reply_len;
	reply[0] = '\0';

	if (ctrl_socket_path(cfg, dest, sizeof(dest)) < 0)
		return -1;

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	memset(&local_addr, 0, sizeof(local_addr));
	local_addr.sun_family = AF_UNIX;
	seq = counter++;
	snprintf(local, sizeof(local), "/tmp/wpa_mini_ctrl_%ld_%d",
		 (long)getpid(), seq);
	strncpy(local_addr.sun_path, local, sizeof(local_addr.sun_path) - 1);
	unlink(local_addr.sun_path);

	if (bind(fd, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0)
		goto out;

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.sun_family = AF_UNIX;
	strncpy(dest_addr.sun_path, dest, sizeof(dest_addr.sun_path) - 1);
	if (connect(fd, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0)
		goto out;

	if (send(fd, cmd, strlen(cmd), 0) < 0)
		goto out;

	for (;;) {
		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
		tv.tv_sec = timeout_ms / 1000;
		tv.tv_usec = (timeout_ms % 1000) * 1000;
		ret = select(fd + 1, &rfds, NULL, NULL, &tv);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			goto out;
		}
		if (ret == 0) {
			errno = ETIMEDOUT;
			ret = -1;
			goto out;
		}
		n = recv(fd, reply, cap - 1, 0);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			goto out;
		}
		reply[n] = '\0';
		if (reply[0] == '<')
			continue;
		*reply_len = (size_t)n;
		ret = 0;
		goto out;
	}

out:
	if (fd >= 0)
		close(fd);
	unlink(local);
	return ret;
}

static int ctrl_ping(const struct app_config *cfg)
{
	char reply[64];
	size_t len = sizeof(reply);

	if (wpa_ctrl_request(cfg, "PING", reply, &len, 500) < 0)
		return -1;
	return strncmp(reply, "PONG", 4) == 0 ? 0 : -1;
}

static int wait_ctrl_ready(const struct app_config *cfg, int timeout_ms)
{
	long long deadline;
	int attempts = 0;

	deadline = now_ms() + timeout_ms;
	while (now_ms() < deadline) {
		attempts++;
		if (ctrl_ping(cfg) == 0) {
			log_msg(cfg, "ctrl ready after %d attempts", attempts);
			return 0;
		}
		usleep(100000);
	}
	log_msg(cfg, "ctrl wait timeout after %d attempts errno=%d", attempts, errno);
	return -1;
}

static int log_child_status(const struct app_config *cfg,
			    const char *label, pid_t pid)
{
	int status;
	pid_t ret;

	ret = waitpid(pid, &status, WNOHANG);
	if (ret == 0) {
		log_msg(cfg, "%s pid=%ld still running", label, (long)pid);
		return 0;
	}
	if (ret == pid) {
		if (WIFEXITED(status)) {
			log_msg(cfg, "%s pid=%ld exited code=%d",
				label, (long)pid, WEXITSTATUS(status));
		} else if (WIFSIGNALED(status)) {
			log_msg(cfg, "%s pid=%ld signaled sig=%d",
				label, (long)pid, WTERMSIG(status));
		} else {
			log_msg(cfg, "%s pid=%ld ended status=%d",
				label, (long)pid, status);
		}
		return 1;
	}

	log_msg(cfg, "%s waitpid pid=%ld failed errno=%d running=%d",
		label, (long)pid, errno, process_running(pid));
	return -1;
}

static int stop_pidfile_process(const char *pidfile)
{
	pid_t pid;
	int i;

	if (read_pid(pidfile, &pid) < 0) {
		unlink(pidfile);
		return 0;
	}

	if (!process_running(pid)) {
		waitpid(pid, NULL, WNOHANG);
		unlink(pidfile);
		return 0;
	}

	kill(pid, SIGTERM);
	for (i = 0; i < 30; i++) {
		if (waitpid(pid, NULL, WNOHANG) == pid)
			break;
		if (!process_running(pid))
			break;
		usleep(100000);
	}

	if (process_running(pid)) {
		kill(pid, SIGKILL);
		waitpid(pid, NULL, WNOHANG);
	}

	unlink(pidfile);
	return 0;
}

static int stop_engine(const struct app_config *cfg)
{
	char reply[64];
	size_t len;

	log_msg(cfg, "engine stop requested");
	len = sizeof(reply);
	wpa_ctrl_request(cfg, "TERMINATE", reply, &len, 500);
	return stop_pidfile_process(cfg->pidfile);
}

static int stop_dhcp(const struct app_config *cfg)
{
	log_msg(cfg, "dhcp stop requested");
	return stop_pidfile_process(cfg->dhcp_pidfile);
}

static int start_engine_process(const struct app_config *cfg)
{
	pid_t pid;
	int child_status;

	log_msg(cfg, "engine start requested iface=%s driver=%s conf=%s ctrl=%s",
		cfg->iface, cfg->driver, cfg->conf, cfg->ctrl_dir);

	if (mkdir_p(cfg->ctrl_dir) < 0) {
		log_msg(cfg, "engine start failed: mkdir ctrl errno=%d", errno);
		return -1;
	}

	stop_engine(cfg);

	pid = fork();
	if (pid < 0) {
		log_msg(cfg, "engine fork failed errno=%d", errno);
		return -1;
	}

	if (pid == 0) {
		char *argv[12];
		int fd;
		int n = 0;
		int rc;
		extern int optind;

		set_engine_log_path(cfg->log_path);
		install_signal_handlers(cfg);
		setsid();
		fd = open(cfg->log_path, O_WRONLY | O_CREAT | O_APPEND, 0600);
		if (fd < 0)
			fd = open("/dev/null", O_RDWR);
		if (fd >= 0) {
			dup2(fd, STDOUT_FILENO);
			dup2(fd, STDERR_FILENO);
			if (fd > STDERR_FILENO)
				close(fd);
		}
		fd = open("/dev/null", O_RDONLY);
		if (fd >= 0) {
			dup2(fd, STDIN_FILENO);
			if (fd > STDERR_FILENO)
				close(fd);
		}

		optind = 1;
		argv[n++] = "wpa_mini_engine";
		argv[n++] = "-D";
		argv[n++] = (char *)cfg->driver;
		argv[n++] = "-i";
		argv[n++] = (char *)cfg->iface;
		argv[n++] = "-c";
		argv[n++] = (char *)cfg->conf;
		argv[n++] = "-C";
		argv[n++] = (char *)cfg->ctrl_dir;
		argv[n] = NULL;
		register_engine_wpa_logging();
		log_msg(cfg,
			"engine child entering wpa_engine_main args='-D %s -i %s -c %s -C %s'",
			cfg->driver, cfg->iface, cfg->conf, cfg->ctrl_dir);
		rc = wpa_engine_main(n, argv);
		log_msg(cfg, "engine child wpa_engine_main returned rc=%d", rc);
		_exit(rc);
	}

	log_msg(cfg, "engine child pid=%ld", (long)pid);

	if (write_pid(cfg->pidfile, pid) < 0) {
		log_msg(cfg, "engine write pidfile failed errno=%d", errno);
		goto fail;
	}

	usleep(250000);
	child_status = log_child_status(cfg, "engine initial check", pid);
	if (child_status == 1) {
		unlink(cfg->pidfile);
		return -1;
	}

	if (wait_ctrl_ready(cfg, 4000) < 0)
		goto fail;

	log_msg(cfg, "engine started");
	return 0;

fail:
	child_status = log_child_status(cfg, "engine failure check", pid);
	if (child_status == 1) {
		unlink(cfg->pidfile);
		return -1;
	}
	log_msg(cfg, "engine start failed, stopping pid=%ld", (long)pid);
	kill(pid, SIGTERM);
	usleep(200000);
	if (process_running(pid))
		kill(pid, SIGKILL);
	waitpid(pid, NULL, WNOHANG);
	unlink(cfg->pidfile);
	return -1;
}

static void shell_single_quote(FILE *fp, const char *s)
{
	fputc('\'', fp);
	for (; *s; s++) {
		if (*s == '\'')
			fputs("'\\''", fp);
		else
			fputc(*s, fp);
	}
	fputc('\'', fp);
}

static int write_dhcp_script(const struct app_config *cfg,
			     const char *dns1, const char *dns2,
			     int use_default_route)
{
	FILE *fp;
	int fd;
	const char *effective_dns1;
	const char *effective_dns2;

	if (!valid_ipv4_or_empty(dns1) || !valid_ipv4_or_empty(dns2)) {
		fprintf(stderr, "DNS must be IPv4 addresses\n");
		return -1;
	}
	effective_dns1 = (dns1 && *dns1) ? dns1 : DEFAULT_DNS1;
	effective_dns2 = (dns2 && *dns2) ? dns2 : DEFAULT_DNS2;

	if (mkdir_parent(cfg->dhcp_script) < 0)
		return -1;

	fd = open(cfg->dhcp_script, O_WRONLY | O_CREAT | O_TRUNC, 0700);
	if (fd < 0)
		return -1;
	fp = fdopen(fd, "w");
	if (!fp) {
		close(fd);
		return -1;
	}

	fprintf(fp, "#!/bin/sh\n");
	fprintf(fp, "RESOLV=");
	shell_single_quote(fp, cfg->dns_path);
	fprintf(fp, "\nDNS1=");
	shell_single_quote(fp, effective_dns1);
	fprintf(fp, "\nDNS2=");
	shell_single_quote(fp, effective_dns2);
	fprintf(fp, "\nDEFAULT_ROUTE=%d\n", use_default_route ? 1 : 0);
	fprintf(fp,
		"run_ifconfig() {\n"
		"  if [ -x /sbin/ifconfig ]; then /sbin/ifconfig \"$@\"; "
		"elif [ -x /bin/ifconfig ]; then /bin/ifconfig \"$@\"; "
		"elif [ -x /usr/sbin/ifconfig ]; then /usr/sbin/ifconfig \"$@\"; "
		"elif [ -x /usr/bin/ifconfig ]; then /usr/bin/ifconfig \"$@\"; "
		"else /bin/busybox ifconfig \"$@\"; fi\n"
		"}\n"
		"run_route() {\n"
		"  if [ -x /sbin/route ]; then /sbin/route \"$@\"; "
		"elif [ -x /bin/route ]; then /bin/route \"$@\"; "
		"elif [ -x /usr/sbin/route ]; then /usr/sbin/route \"$@\"; "
		"elif [ -x /usr/bin/route ]; then /usr/bin/route \"$@\"; "
		"else /bin/busybox route \"$@\"; fi\n"
		"}\n"
		"case \"$1\" in\n"
		"deconfig)\n"
		"  run_ifconfig \"$interface\" 0.0.0.0 2>/dev/null\n"
		"  [ \"$DEFAULT_ROUTE\" = 1 ] && run_route del default dev \"$interface\" 2>/dev/null\n"
		"  ;;\n"
		"bound|renew)\n"
		"  if [ -n \"$broadcast\" ]; then\n"
		"    run_ifconfig \"$interface\" \"$ip\" netmask \"$subnet\" broadcast \"$broadcast\" up\n"
		"  else\n"
		"    run_ifconfig \"$interface\" \"$ip\" netmask \"$subnet\" up\n"
		"  fi\n"
		"  if [ \"$DEFAULT_ROUTE\" = 1 ]; then\n"
		"    run_route del default dev \"$interface\" 2>/dev/null\n"
		"    set -- $router\n"
		"    [ -n \"$1\" ] && run_route add default gw \"$1\" dev \"$interface\" 2>/dev/null\n"
		"  fi\n"
		"  DIR=${RESOLV%%/*}\n"
		"  [ \"$DIR\" != \"$RESOLV\" ] && mkdir -p \"$DIR\" 2>/dev/null\n"
		"  : > \"$RESOLV\"\n"
		"  if [ -n \"$DNS1$DNS2\" ]; then\n"
		"    [ -n \"$DNS1\" ] && echo \"nameserver $DNS1\" >> \"$RESOLV\"\n"
		"    [ -n \"$DNS2\" ] && echo \"nameserver $DNS2\" >> \"$RESOLV\"\n"
		"  else\n"
		"    for d in $dns; do echo \"nameserver $d\" >> \"$RESOLV\"; done\n"
		"  fi\n"
		"  ;;\n"
		"esac\n"
		"exit 0\n");

	if (fclose(fp) != 0)
		return -1;
	return chmod(cfg->dhcp_script, 0700);
}

static int start_dhcp(const struct app_config *cfg,
		      const char *dns1, const char *dns2,
		      int use_default_route)
{
	pid_t pid;

	log_msg(cfg, "dhcp start requested iface=%s dns1=%s dns2=%s route=%d",
		cfg->iface, dns1 ? dns1 : "", dns2 ? dns2 : "",
		use_default_route);

	if (write_dhcp_script(cfg, dns1, dns2, use_default_route) < 0) {
		log_msg(cfg, "dhcp script write failed errno=%d", errno);
		return -1;
	}

	stop_dhcp(cfg);

	pid = fork();
	if (pid < 0) {
		log_msg(cfg, "dhcp fork failed errno=%d", errno);
		return -1;
	}

	if (pid == 0) {
		int fd;

		setsid();
		fd = open(cfg->log_path, O_WRONLY | O_CREAT | O_APPEND, 0600);
		if (fd < 0)
			fd = open("/dev/null", O_RDWR);
		if (fd >= 0) {
			dup2(fd, STDOUT_FILENO);
			dup2(fd, STDERR_FILENO);
			if (fd > STDERR_FILENO)
				close(fd);
		}
		fd = open("/dev/null", O_RDONLY);
		if (fd >= 0) {
			dup2(fd, STDIN_FILENO);
			if (fd > STDERR_FILENO)
				close(fd);
		}

		execl(cfg->udhcpc, cfg->udhcpc,
		      "-i", cfg->iface,
		      "-s", cfg->dhcp_script,
		      "-f",
		      "-t", "5",
		      "-T", "5",
		      (char *)NULL);
		_exit(127);
	}

	log_msg(cfg, "dhcp child pid=%ld", (long)pid);

	if (write_pid(cfg->dhcp_pidfile, pid) < 0) {
		log_msg(cfg, "dhcp write pidfile failed errno=%d", errno);
		goto fail;
	}

	usleep(200000);
	if (!process_running(pid)) {
		log_msg(cfg, "dhcp exited immediately");
		unlink(cfg->dhcp_pidfile);
		return -1;
	}

	log_msg(cfg, "dhcp started");
	return 0;

fail:
	log_msg(cfg, "dhcp start failed, stopping pid=%ld", (long)pid);
	kill(pid, SIGTERM);
	usleep(100000);
	if (process_running(pid))
		kill(pid, SIGKILL);
	waitpid(pid, NULL, WNOHANG);
	unlink(cfg->dhcp_pidfile);
	return -1;
}

static void html_escape(char *out, size_t outsz, const char *in)
{
	size_t used = 0;
	const char *rep;

	if (!outsz)
		return;

	while (*in && used + 1 < outsz) {
		switch (*in) {
		case '&':
			rep = "&amp;";
			break;
		case '<':
			rep = "&lt;";
			break;
		case '>':
			rep = "&gt;";
			break;
		case '"':
			rep = "&quot;";
			break;
		case '\'':
			rep = "&#39;";
			break;
		default:
			rep = NULL;
			break;
		}

		if (rep) {
			size_t len = strlen(rep);
			if (used + len >= outsz)
				break;
			memcpy(out + used, rep, len);
			used += len;
		} else {
			out[used++] = *in;
		}
		in++;
	}
	out[used] = '\0';
}

static void json_escape(char *out, size_t outsz, const char *in)
{
	size_t used = 0;

	if (!outsz)
		return;

	while (*in && used + 1 < outsz) {
		if (*in == '"' || *in == '\\') {
			if (used + 2 >= outsz)
				break;
			out[used++] = '\\';
			out[used++] = *in;
		} else if ((unsigned char)*in < 32) {
			if (used + 7 >= outsz)
				break;
			used += snprintf(out + used, outsz - used,
					 "\\u%04x", (unsigned char)*in);
		} else {
			out[used++] = *in;
		}
		in++;
	}
	out[used] = '\0';
}

static int hex_value(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static void url_decode(char *out, size_t outsz, const char *in, size_t inlen)
{
	size_t i, used = 0;

	if (!outsz)
		return;

	for (i = 0; i < inlen && used + 1 < outsz; i++) {
		if (in[i] == '+') {
			out[used++] = ' ';
		} else if (in[i] == '%' && i + 2 < inlen) {
			int hi = hex_value(in[i + 1]);
			int lo = hex_value(in[i + 2]);
			if (hi >= 0 && lo >= 0) {
				out[used++] = (char)((hi << 4) | lo);
				i += 2;
			} else {
				out[used++] = in[i];
			}
		} else {
			out[used++] = in[i];
		}
	}
	out[used] = '\0';
}

static int form_value(const char *body, const char *key,
		      char *out, size_t outsz)
{
	size_t keylen = strlen(key);
	const char *p = body;

	while (*p) {
		const char *eq = strchr(p, '=');
		const char *amp = strchr(p, '&');
		const char *end = amp ? amp : p + strlen(p);

		if (eq && eq < end &&
		    (size_t)(eq - p) == keylen &&
		    strncmp(p, key, keylen) == 0) {
			url_decode(out, outsz, eq + 1, (size_t)(end - eq - 1));
			return 1;
		}

		if (!amp)
			break;
		p = amp + 1;
	}

	if (outsz)
		out[0] = '\0';
	return 0;
}

static int read_current_ssid(const char *conf, char *out, size_t outsz)
{
	FILE *fp;
	char line[256];

	if (outsz)
		out[0] = '\0';

	fp = fopen(conf, "r");
	if (!fp)
		return -1;

	while (fgets(line, sizeof(line), fp)) {
		char *p = line;
		while (*p == ' ' || *p == '\t')
			p++;
		if (strncmp(p, "ssid=", 5) == 0) {
			p += 5;
			if (*p == '"') {
				size_t used = 0;
				p++;
				while (*p && *p != '"' && used + 1 < outsz) {
					if (*p == '\\' && p[1])
						p++;
					out[used++] = *p++;
				}
				out[used] = '\0';
			} else {
				size_t len = strcspn(p, "\r\n");
				if (len >= outsz)
					len = outsz - 1;
				memcpy(out, p, len);
				out[len] = '\0';
			}
			fclose(fp);
			return 0;
		}
	}

	fclose(fp);
	return -1;
}

static void parse_status_field(char *dst, size_t dstsz,
			       const char *status, const char *key)
{
	size_t keylen = strlen(key);
	const char *p = status;

	if (dstsz)
		dst[0] = '\0';

	while (*p) {
		const char *end = strchr(p, '\n');
		size_t len = end ? (size_t)(end - p) : strlen(p);
		if (len > keylen && strncmp(p, key, keylen) == 0 &&
		    p[keylen] == '=') {
			size_t vlen = len - keylen - 1;
			if (vlen >= dstsz)
				vlen = dstsz - 1;
			memcpy(dst, p + keylen + 1, vlen);
			dst[vlen] = '\0';
			return;
		}
		if (!end)
			break;
		p = end + 1;
	}
}

static int read_iface_ipv4(const char *iface, char *out, size_t outsz)
{
	int fd;
	struct ifreq ifr;
	struct sockaddr_in *sin;

	if (outsz)
		out[0] = '\0';
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
		close(fd);
		return -1;
	}
	close(fd);
	sin = (struct sockaddr_in *)&ifr.ifr_addr;
	if (!inet_ntop(AF_INET, &sin->sin_addr, out, outsz))
		return -1;
	return 0;
}

static int wait_ipv4_ready(const struct app_config *cfg, int timeout_ms)
{
	int elapsed = 0;
	char ip[64];

	while (elapsed < timeout_ms) {
		if (read_iface_ipv4(cfg->iface, ip, sizeof(ip)) == 0 && ip[0])
			return 0;
		usleep(250000);
		elapsed += 250;
	}

	return -1;
}

static int run_quiet(char *const argv[])
{
	pid_t pid;
	pid_t waited;
	int status;

	pid = fork();
	if (pid < 0)
		return -1;

	if (pid == 0) {
		int fd = open("/dev/null", O_RDWR);
		if (fd >= 0) {
			dup2(fd, STDIN_FILENO);
			dup2(fd, STDOUT_FILENO);
			dup2(fd, STDERR_FILENO);
			if (fd > STDERR_FILENO)
				close(fd);
		}
		execvp(argv[0], argv);
		_exit(127);
	}

	do {
		waited = waitpid(pid, &status, 0);
	} while (waited < 0 && errno == EINTR);

	if (waited < 0)
		return -1;
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return -1;
	return 0;
}

static int run_tool_quiet(const char *tool, char *const args[])
{
	const char *dirs[] = { "/sbin", "/bin", "/usr/sbin", "/usr/bin", NULL };
	char path[64];
	char *argv[8];
	int i;
	int j;
	int n;

	for (i = 0; dirs[i]; i++) {
		n = snprintf(path, sizeof(path), "%s/%s", dirs[i], tool);
		if (n < 0 || (size_t)n >= sizeof(path))
			continue;
		if (access(path, X_OK) != 0)
			continue;
		argv[0] = path;
		for (j = 0; args[j] && j < 6; j++)
			argv[j + 1] = args[j];
		argv[j + 1] = NULL;
		return run_quiet(argv);
	}

	if (access("/bin/busybox", X_OK) == 0) {
		argv[0] = "/bin/busybox";
		argv[1] = (char *)tool;
		for (j = 0; args[j] && j < 5; j++)
			argv[j + 2] = args[j];
		argv[j + 2] = NULL;
		return run_quiet(argv);
	}

	argv[0] = (char *)tool;
	for (j = 0; args[j] && j < 6; j++)
		argv[j + 1] = args[j];
	argv[j + 1] = NULL;
	return run_quiet(argv);
}

static void deconfigure_iface(const struct app_config *cfg)
{
	char *route_args[] = { "del", "default", "dev",
			       (char *)cfg->iface, NULL };
	char *ifconfig_args[] = { (char *)cfg->iface, "0.0.0.0", NULL };

	run_tool_quiet("route", route_args);
	run_tool_quiet("ifconfig", ifconfig_args);
}

static int read_gateway(const char *iface, char *out, size_t outsz)
{
	FILE *fp;
	char line[256];

	if (outsz)
		out[0] = '\0';
	fp = fopen("/proc/net/route", "r");
	if (!fp)
		return -1;

	if (!fgets(line, sizeof(line), fp)) {
		fclose(fp);
		return -1;
	}
	while (fgets(line, sizeof(line), fp)) {
		char ifn[IFNAMSIZ];
		unsigned long dest;
		unsigned long gw;
		unsigned int flags;
		struct in_addr a;

		if (sscanf(line, "%15s %lx %lx %x", ifn, &dest, &gw, &flags) != 4)
			continue;
		if (strcmp(ifn, iface) != 0 || dest != 0 || !(flags & 0x2))
			continue;
		a.s_addr = (in_addr_t)gw;
		inet_ntop(AF_INET, &a, out, outsz);
		fclose(fp);
		return 0;
	}

	fclose(fp);
	return -1;
}

static void read_dns_file(const char *path, char *out, size_t outsz)
{
	FILE *fp;
	char line[256];
	int count = 0;

	if (outsz)
		out[0] = '\0';

	fp = fopen(path, "r");
	if (!fp)
		return;

	while (fgets(line, sizeof(line), fp)) {
		char dns[64];
		if (sscanf(line, "nameserver %63s", dns) != 1)
			continue;
		if (count)
			buf_append(out, outsz, ", ");
		buf_append(out, outsz, "%s", dns);
		count++;
		if (count >= 3)
			break;
	}
	fclose(fp);
}

static void get_runtime_status(const struct app_config *cfg,
			       struct runtime_status *st)
{
	char reply[STATUS_REPLY_MAX];
	size_t len;

	memset(st, 0, sizeof(*st));
	if (read_pid(cfg->pidfile, &st->engine_pid) == 0)
		st->engine_running = process_running(st->engine_pid);
	if (read_pid(cfg->dhcp_pidfile, &st->dhcp_pid) == 0)
		st->dhcp_running = process_running(st->dhcp_pid);

	if (st->engine_running) {
		len = sizeof(reply);
		if (wpa_ctrl_request(cfg, "STATUS", reply, &len, 800) == 0) {
			parse_status_field(st->wpa_state, sizeof(st->wpa_state),
					   reply, "wpa_state");
			parse_status_field(st->ssid, sizeof(st->ssid),
					   reply, "ssid");
			parse_status_field(st->bssid, sizeof(st->bssid),
					   reply, "bssid");
			parse_status_field(st->key_mgmt, sizeof(st->key_mgmt),
					   reply, "key_mgmt");
		} else {
			log_msg(cfg, "status ctrl request failed errno=%d", errno);
		}
	}
	if (!st->ssid[0])
		read_current_ssid(cfg->conf, st->ssid, sizeof(st->ssid));
	if (!st->wpa_state[0] && st->engine_running)
		snprintf(st->wpa_state, sizeof(st->wpa_state), "STARTING");
	if (!st->wpa_state[0])
		snprintf(st->wpa_state, sizeof(st->wpa_state), "STOPPED");

	read_iface_ipv4(cfg->iface, st->ip, sizeof(st->ip));
	read_gateway(cfg->iface, st->gateway, sizeof(st->gateway));
	read_dns_file(cfg->dns_path, st->dns, sizeof(st->dns));
}

static int wait_wpa_completed(const struct app_config *cfg, int timeout_ms)
{
	long long deadline = now_ms() + timeout_ms;
	int attempts = 0;

	while (now_ms() < deadline) {
		struct runtime_status st;
		get_runtime_status(cfg, &st);
		attempts++;
		log_msg(cfg, "wpa state poll %d state=%s engine=%d ip=%s",
			attempts, st.wpa_state, st.engine_running, st.ip);
		if (strcmp(st.wpa_state, "COMPLETED") == 0) {
			log_msg(cfg, "wpa completed after %d polls", attempts);
			return 0;
		}
		if (!st.engine_running) {
			log_msg(cfg, "wpa engine stopped while waiting");
			return -1;
		}
		usleep(250000);
	}
	log_msg(cfg, "wpa completed timeout after %d polls", attempts);
	return -1;
}

static int ensure_scan_engine(const struct app_config *cfg)
{
	pid_t pid;

	if (read_pid(cfg->pidfile, &pid) == 0 && process_running(pid) &&
	    ctrl_ping(cfg) == 0)
		return 0;

	if (write_base_config(cfg->conf, cfg->ctrl_dir) < 0)
		return -1;
	return start_engine_process(cfg);
}

static int scan_has_rows(const char *text)
{
	const char *p;

	p = strchr(text, '\n');
	return p && p[1];
}

static int run_scan(const struct app_config *cfg, char *out, size_t outsz)
{
	char *reply;
	size_t len;
	size_t out_cap;
	int i;
	int ret = -1;

	log_msg(cfg, "scan requested");
	if (outsz)
		out[0] = '\0';
	out_cap = outsz;
	reply = calloc(1, CTRL_REPLY_MAX);
	if (!reply) {
		log_msg(cfg, "scan failed: allocation failed");
		return -1;
	}
	if (ensure_scan_engine(cfg) < 0) {
		log_msg(cfg, "scan failed: engine unavailable");
		goto out;
	}

	len = CTRL_REPLY_MAX;
	if (wpa_ctrl_request(cfg, "SCAN", reply, &len, 1000) < 0) {
		log_msg(cfg, "scan trigger failed errno=%d", errno);
		goto out;
	}
	log_msg(cfg, "scan trigger reply=%s", reply);
	if (strncmp(reply, "OK", 2) != 0 && strncmp(reply, "FAIL-BUSY", 9) != 0)
		goto out;

	for (i = 0; i < 32; i++) {
		usleep(250000);
		len = out_cap;
		if (wpa_ctrl_request(cfg, "SCAN_RESULTS", out, &len, 1200) == 0 &&
		    scan_has_rows(out)) {
			log_msg(cfg, "scan results ready bytes=%lu",
				(unsigned long)len);
			ret = 0;
			goto out;
		}
	}
	len = out_cap;
	if (wpa_ctrl_request(cfg, "SCAN_RESULTS", out, &len, 1200) == 0) {
		log_msg(cfg, "scan results empty bytes=%lu", (unsigned long)len);
		ret = 0;
		goto out;
	}
	log_msg(cfg, "scan results timeout");
out:
	free(reply);
	return ret;
}

static int send_all(const struct app_config *cfg, int fd,
		    const char *buf, size_t len, const char *label)
{
	size_t total = len;

	while (len) {
		ssize_t n = send(fd, buf, len, MSG_NOSIGNAL);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			log_msg(cfg, "http send %s failed errno=%d remaining=%lu",
				label ? label : "", errno, (unsigned long)len);
			return -1;
		}
		buf += n;
		len -= (size_t)n;
	}
	log_msg(cfg, "http send %s ok bytes=%lu", label ? label : "",
		(unsigned long)total);
	return 0;
}

static void http_send(int fd, const struct app_config *cfg,
		      int code, const char *status,
		      const char *ctype, const char *body)
{
	char header[256];
	size_t body_len = strlen(body);
	int header_len;

	header_len = snprintf(header, sizeof(header),
			      "HTTP/1.1 %d %s\r\n"
			      "Content-Type: %s\r\n"
			      "Content-Length: %lu\r\n"
			      "Connection: close\r\n"
			      "Cache-Control: no-store\r\n"
			      "\r\n",
			      code, status, ctype, (unsigned long)body_len);
	if (header_len < 0)
		return;

	log_msg(cfg, "http response code=%d status=%s body=%lu",
		code, status, (unsigned long)body_len);
	if (send_all(cfg, fd, header, (size_t)header_len, "header") < 0)
		return;
	send_all(cfg, fd, body, body_len, "body");
}

static void http_redirect(int fd, const struct app_config *cfg,
			  const char *location)
{
	char header[256];
	int len;

	len = snprintf(header, sizeof(header),
		       "HTTP/1.1 303 See Other\r\n"
		       "Location: %s\r\n"
		       "Content-Length: 0\r\n"
		       "Connection: close\r\n"
		       "Cache-Control: no-store\r\n"
		       "\r\n",
		       location);
	log_msg(cfg, "http redirect location=%s", location);
	if (len > 0)
		send_all(cfg, fd, header, (size_t)len, "redirect");
}

static void build_scan_html(const char *scan_text, char *out, size_t outsz)
{
	char *copy;
	char *save;
	char *line;
	int rows = 0;

	if (outsz)
		out[0] = '\0';
	if (!scan_text || !*scan_text)
		return;

	copy = malloc(SCAN_TEXT_MAX);
	if (!copy)
		return;
	snprintf(copy, SCAN_TEXT_MAX, "%s", scan_text);
	buf_append(out, outsz,
		   "<section class=\"panel\"><div class=\"formtop\"><div>"
		   "<div class=\"title\">附近 WiFi</div>"
		   "<div class=\"hint\">扫描结果来自当前 STA 接口</div>"
		   "</div></div><div class=\"tablewrap\"><table><thead><tr>"
		   "<th>SSID</th><th>信号</th><th>安全</th><th>BSSID</th>"
		   "</tr></thead><tbody>");

	line = strtok_r(copy, "\n", &save);
	while ((line = strtok_r(NULL, "\n", &save)) != NULL) {
		char *fields[5];
		char *p = line;
		int i;
		char esc_ssid[256], esc_flags[256], esc_bssid[128], esc_signal[64];

		for (i = 0; i < 4; i++) {
			fields[i] = p;
			p = strchr(p, '\t');
			if (!p)
				break;
			*p++ = '\0';
		}
		if (i < 4)
			continue;
		fields[4] = p;
		if (!fields[4][0])
			continue;
		html_escape(esc_bssid, sizeof(esc_bssid), fields[0]);
		html_escape(esc_signal, sizeof(esc_signal), fields[2]);
		html_escape(esc_flags, sizeof(esc_flags), fields[3]);
		html_escape(esc_ssid, sizeof(esc_ssid), fields[4]);
		buf_append(out, outsz,
			   "<tr><td>%s</td><td>%s dBm</td><td>%s</td><td>%s</td></tr>",
			   esc_ssid, esc_signal, esc_flags, esc_bssid);
		rows++;
	}

	if (!rows)
		buf_append(out, outsz, "<tr><td colspan=\"4\">未发现网络</td></tr>");
	buf_append(out, outsz, "</tbody></table></div></section>");
	free(copy);
}

static void render_page(int fd, const struct app_config *cfg,
			const char *message, const char *scan_text)
{
	struct runtime_status st;
	char esc_ssid[256];
	char esc_iface[128];
	char esc_msg[512];
	char esc_state[128];
	char esc_bssid[128];
	char esc_ip[128];
	char esc_gw[128];
	char esc_dns[256];
	char esc_dns_path[512];
	char *scan_html;
	char *body;
	const char *state_color;
	const char *state_label;

	log_msg(cfg, "render page message=%s scan=%d",
		message ? message : "", scan_text && *scan_text ? 1 : 0);
	scan_html = calloc(1, SCAN_HTML_MAX);
	body = calloc(1, PAGE_BODY_MAX);
	if (!scan_html || !body) {
		free(scan_html);
		free(body);
		log_msg(cfg, "render page allocation failed");
		http_send(fd, cfg, 500, "Internal Server Error", "text/plain",
			  "out of memory\n");
		return;
	}

	get_runtime_status(cfg, &st);
	html_escape(esc_ssid, sizeof(esc_ssid), st.ssid);
	html_escape(esc_iface, sizeof(esc_iface), cfg->iface);
	html_escape(esc_msg, sizeof(esc_msg), message ? message : "");
	html_escape(esc_state, sizeof(esc_state), st.wpa_state);
	html_escape(esc_bssid, sizeof(esc_bssid), st.bssid);
	html_escape(esc_ip, sizeof(esc_ip), st.ip);
	html_escape(esc_gw, sizeof(esc_gw), st.gateway);
	html_escape(esc_dns, sizeof(esc_dns), st.dns);
	html_escape(esc_dns_path, sizeof(esc_dns_path), cfg->dns_path);
	build_scan_html(scan_text, scan_html, SCAN_HTML_MAX);

	state_color = strcmp(st.wpa_state, "COMPLETED") == 0 ? "#257a4b" :
		      st.engine_running ? "#9b6b13" : "#a34444";
	state_label = strcmp(st.wpa_state, "COMPLETED") == 0 ? "已连接" :
		      st.engine_running ? "连接中" : "已停止";

	snprintf(body, PAGE_BODY_MAX,
		 "<!doctype html><html><head><meta charset=\"utf-8\">"
		 "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
		 "<title>WPA Mini</title>"
		 "<style>"
		 "*{box-sizing:border-box}body{margin:0;font-family:Arial,'Microsoft YaHei',sans-serif;background:#f5f7f4;color:#18251d}"
		 "@keyframes rise{from{opacity:.65;transform:translateY(6px)}to{opacity:1;transform:none}}"
		 ".bar{background:#fff;border-bottom:1px solid #dde5de}.head{max-width:980px;margin:auto;padding:16px;display:flex;justify-content:space-between;align-items:center;gap:12px}"
		 "main{max-width:980px;margin:16px auto 24px;padding:0 16px}.brand{font-size:21px;font-weight:700}.sub,.hint{font-size:12px;color:#66756b;margin-top:3px}"
		 ".pill{border-radius:999px;padding:7px 11px;background:%s;color:#fff;font-size:13px;font-weight:700;white-space:nowrap}"
		 ".summary{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:14px}.layout{display:grid;grid-template-columns:1.35fr .9fr;gap:14px}.panel{background:#fff;border:1px solid #d9e2dc;border-radius:8px;margin-bottom:14px;box-shadow:0 4px 14px rgba(24,37,29,.05);overflow:hidden;animation:rise .22s ease-out}"
		 ".formtop{border-bottom:1px solid #e7ece8;padding:14px 16px}.title{font-size:16px;font-weight:700}.pad{padding:16px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:9px}"
		 ".kv{border-bottom:1px solid #edf1ee;padding:8px 0}.summary .kv{background:#fff;border:1px solid #d9e2dc;border-radius:8px;padding:11px 13px}.k{font-size:12px;color:#6d7b71}.v{font-size:14px;font-weight:700;word-break:break-all;margin-top:3px}"
		 ".twocol{display:grid;grid-template-columns:1fr 1fr;gap:10px}label{display:block;font-size:13px;font-weight:700;margin:11px 0 5px}"
		 "input{width:100%%;height:40px;border:1px solid #b8c5bb;border-radius:6px;padding:9px 10px;font-size:14px;background:#fff;outline:none;transition:border-color .15s,box-shadow .15s}"
		 "input:focus{border-color:#2f7d4f;box-shadow:0 0 0 3px #dfeee5}.check{display:flex;gap:7px;align-items:center;margin:12px 0}.check input{width:auto;height:auto}.check label{margin:0;font-weight:600}"
		 ".actions{display:flex;gap:9px;flex-wrap:wrap;margin-top:14px}button{height:40px;border:1px solid #2f7d4f;border-radius:6px;background:#2f7d4f;color:#fff;font-size:14px;font-weight:700;padding:0 17px;cursor:pointer;transition:background .15s,transform .15s}button:hover{transform:translateY(-1px);background:#256f43}"
		 "button.alt,button.scan{background:#fff;color:#2f7d4f}.msg{background:#f0f7f2;border:1px solid #cfe1d4;border-radius:8px;color:#235a39;padding:12px 14px;margin-bottom:14px}.tablewrap{overflow:auto}"
		 "table{width:100%%;border-collapse:collapse;font-size:13px}th,td{text-align:left;border-bottom:1px solid #e7ece8;padding:9px;vertical-align:top}th{color:#596960;background:#f8faf7;font-weight:700}"
		 "@media(max-width:760px){.head{align-items:flex-start}.layout,.grid,.twocol,.summary{grid-template-columns:1fr}}"
		 "</style></head><body><div class=\"bar\"><div class=\"head\"><div><div class=\"brand\">WPA Mini</div><div class=\"sub\">WiFi STA 控制台</div></div><div class=\"pill\">%s</div></div></div><main>"
		 "%s%s%s"
		 "<div class=\"summary\">"
		 "<div class=\"kv\"><div class=\"k\">接口</div><div class=\"v\">%s</div></div>"
		 "<div class=\"kv\"><div class=\"k\">WPA 状态</div><div class=\"v\">%s</div></div>"
		 "<div class=\"kv\"><div class=\"k\">SSID</div><div class=\"v\">%s</div></div>"
		 "<div class=\"kv\"><div class=\"k\">IP</div><div class=\"v\">%s</div></div>"
		 "</div>"
		 "<div class=\"layout\"><section class=\"panel\"><div class=\"formtop\"><div><div class=\"title\">连接网络</div><div class=\"hint\">WPA/WPA2-PSK，DNS 文件：%s</div></div></div>"
		 "<div class=\"pad\"><form method=\"post\" action=\"/connect\">"
		 "<label>SSID</label><input name=\"ssid\" maxlength=\"32\" value=\"%s\" autocomplete=\"off\" required>"
		 "<label>BSSID</label><input name=\"bssid\" maxlength=\"17\" placeholder=\"可选，锁定指定 AP\" autocomplete=\"off\">"
		 "<label>密码或 64 位 HEX PSK</label><input name=\"psk\" type=\"password\" autocomplete=\"off\" required>"
		 "<div class=\"twocol\"><div><label>DNS 1</label><input name=\"dns1\" value=\"" DEFAULT_DNS1 "\" inputmode=\"decimal\"></div>"
		 "<div><label>DNS 2</label><input name=\"dns2\" value=\"" DEFAULT_DNS2 "\" inputmode=\"decimal\"></div></div>"
		 "<div class=\"check\"><input id=\"hidden\" name=\"hidden\" value=\"1\" type=\"checkbox\"><label for=\"hidden\">隐藏 SSID</label></div>"
		 "<div class=\"check\"><input id=\"route\" name=\"route\" value=\"1\" type=\"checkbox\"><label for=\"route\">使用 STA 作为默认路由</label></div>"
		 "<div class=\"actions\"><button type=\"submit\">连接</button></div></form>"
		 "<div class=\"actions\"><form method=\"post\" action=\"/scan\"><button class=\"scan\" type=\"submit\">扫描 WiFi</button></form>"
		 "<form method=\"post\" action=\"/disconnect\"><button class=\"alt\" type=\"submit\">断开</button></form></div></div></section>"
		 "<section class=\"panel\"><div class=\"formtop\"><div class=\"title\">运行信息</div><div class=\"hint\">当前接口状态</div></div><div class=\"pad\"><div class=\"grid\">"
		 "<div class=\"kv\"><div class=\"k\">BSSID</div><div class=\"v\">%s</div></div>"
		 "<div class=\"kv\"><div class=\"k\">网关</div><div class=\"v\">%s</div></div>"
		 "<div class=\"kv\"><div class=\"k\">DNS</div><div class=\"v\">%s</div></div>"
		 "<div class=\"kv\"><div class=\"k\">引擎 PID</div><div class=\"v\">%ld</div></div>"
		 "<div class=\"kv\"><div class=\"k\">DHCP PID</div><div class=\"v\">%ld</div></div>"
		 "</div></div></section></div>%s</main></body></html>",
		 state_color,
		 state_label,
		 message ? "<section class=\"msg\">" : "",
		 message ? esc_msg : "",
		 message ? "</section>" : "",
		 esc_iface,
		 esc_state,
		 esc_ssid[0] ? esc_ssid : "-",
		 esc_ip[0] ? esc_ip : "-",
		 esc_dns_path,
		 esc_ssid,
		 esc_bssid[0] ? esc_bssid : "-",
		 esc_gw[0] ? esc_gw : "-",
		 esc_dns[0] ? esc_dns : "-",
		 st.engine_running ? (long)st.engine_pid : 0L,
		 st.dhcp_running ? (long)st.dhcp_pid : 0L,
		 scan_html);

	http_send(fd, cfg, 200, "OK", "text/html; charset=utf-8", body);
	free(scan_html);
	free(body);
}

static void render_status(int fd, const struct app_config *cfg)
{
	struct runtime_status st;
	char esc_ssid[256], esc_state[128], esc_bssid[128], esc_ip[128];
	char esc_gw[128], esc_dns[256], esc_key[128], esc_iface[128];
	char esc_dns_path[512], body[2048];

	log_msg(cfg, "render status");
	get_runtime_status(cfg, &st);
	json_escape(esc_iface, sizeof(esc_iface), cfg->iface);
	json_escape(esc_ssid, sizeof(esc_ssid), st.ssid);
	json_escape(esc_state, sizeof(esc_state), st.wpa_state);
	json_escape(esc_bssid, sizeof(esc_bssid), st.bssid);
	json_escape(esc_ip, sizeof(esc_ip), st.ip);
	json_escape(esc_gw, sizeof(esc_gw), st.gateway);
	json_escape(esc_dns, sizeof(esc_dns), st.dns);
	json_escape(esc_key, sizeof(esc_key), st.key_mgmt);
	json_escape(esc_dns_path, sizeof(esc_dns_path), cfg->dns_path);

	snprintf(body, sizeof(body),
		 "{\"engine_running\":%s,\"engine_pid\":%ld,"
		 "\"dhcp_running\":%s,\"dhcp_pid\":%ld,"
		 "\"iface\":\"%s\",\"wpa_state\":\"%s\",\"ssid\":\"%s\","
		 "\"bssid\":\"%s\",\"key_mgmt\":\"%s\",\"ip\":\"%s\","
		 "\"gateway\":\"%s\",\"dns\":\"%s\",\"dns_path\":\"%s\","
		 "\"port\":%d}\n",
		 st.engine_running ? "true" : "false",
		 st.engine_running ? (long)st.engine_pid : 0L,
		 st.dhcp_running ? "true" : "false",
		 st.dhcp_running ? (long)st.dhcp_pid : 0L,
		 esc_iface, esc_state, esc_ssid, esc_bssid, esc_key,
		 esc_ip, esc_gw, esc_dns, esc_dns_path, cfg->port);
	http_send(fd, cfg, 200, "OK", "application/json", body);
}

static int content_length(const char *headers)
{
	const char *p = headers;

	while (*p) {
		const char *line_end = strstr(p, "\r\n");
		size_t len = line_end ? (size_t)(line_end - p) : strlen(p);

		if (len >= 15 && strncasecmp(p, "Content-Length:", 15) == 0) {
			const char *v = p + 15;
			const char *line_limit = p + len;
			long value = 0;

			while (v < line_limit && (*v == ' ' || *v == '\t'))
				v++;
			if (v >= line_limit || !isdigit((unsigned char)*v))
				return -1;
			while (v < line_limit && isdigit((unsigned char)*v)) {
				value = value * 10 + (*v - '0');
				if (value > HTTP_BODY_MAX)
					return HTTP_BODY_MAX + 1;
				v++;
			}
			while (v < line_limit && (*v == ' ' || *v == '\t'))
				v++;
			if (v != line_limit)
				return -1;
			return (int)value;
		}

		if (!line_end)
			break;
		p = line_end + 2;
		if (p[0] == '\r' && p[1] == '\n')
			break;
	}
	return 0;
}

static void handle_connect(int fd, const struct app_config *cfg,
			   const char *body)
{
	char ssid[96];
	char bssid[32];
	char psk[128];
	char dns1[64];
	char dns2[64];
	char value[16];
	int hidden;
	int use_route;

	form_value(body, "ssid", ssid, sizeof(ssid));
	form_value(body, "bssid", bssid, sizeof(bssid));
	form_value(body, "psk", psk, sizeof(psk));
	form_value(body, "dns1", dns1, sizeof(dns1));
	form_value(body, "dns2", dns2, sizeof(dns2));
	hidden = form_value(body, "hidden", value, sizeof(value)) && value[0];
	use_route = form_value(body, "route", value, sizeof(value)) && value[0];
	if (!dns1[0])
		snprintf(dns1, sizeof(dns1), "%s", DEFAULT_DNS1);
	if (!dns2[0])
		snprintf(dns2, sizeof(dns2), "%s", DEFAULT_DNS2);
	log_msg(cfg, "connect request ssid=%s bssid=%s hidden=%d route=%d dns1=%s dns2=%s",
		ssid, bssid, hidden, use_route, dns1, dns2);

	if (!valid_ipv4_or_empty(dns1) || !valid_ipv4_or_empty(dns2)) {
		log_msg(cfg, "connect rejected: invalid dns");
		render_page(fd, cfg, "DNS 必须是有效的 IPv4 地址。", NULL);
		return;
	}
	if (!valid_bssid_or_empty(bssid)) {
		log_msg(cfg, "connect rejected: invalid bssid");
		render_page(fd, cfg, "BSSID 可以留空，填写时必须是 MAC 地址格式。", NULL);
		return;
	}

	if (write_config(cfg->conf, cfg->ctrl_dir, ssid, psk, bssid, hidden) < 0) {
		log_msg(cfg, "connect rejected: config write failed errno=%d", errno);
		render_page(fd, cfg, "配置写入失败，请检查 SSID 和密码长度。", NULL);
		return;
	}

	stop_dhcp(cfg);
	deconfigure_iface(cfg);

	if (start_engine_process(cfg) < 0) {
		render_page(fd, cfg, "配置已写入，但内置 WPA 引擎启动失败。", NULL);
		return;
	}

	if (wait_wpa_completed(cfg, 20000) < 0) {
		stop_engine(cfg);
		render_page(fd, cfg, "内置 WPA 引擎已启动，但无线关联尚未完成。", NULL);
		return;
	}

	if (start_dhcp(cfg, dns1, dns2, use_route) < 0) {
		render_page(fd, cfg, "WiFi 已连接，但 udhcpc 启动失败。", NULL);
		return;
	}

	if (wait_ipv4_ready(cfg, 8000) < 0) {
		log_msg(cfg, "connect warning: DHCP no IP yet");
		render_page(fd, cfg, "WiFi 已连接，但 DHCP 暂未分配 IP。", NULL);
		return;
	}

	log_msg(cfg, "connect completed");
	http_redirect(fd, cfg, "/");
}

static void handle_scan_page(int fd, const struct app_config *cfg)
{
	char *scan;

	scan = calloc(1, SCAN_TEXT_MAX);
	if (!scan) {
		http_send(fd, cfg, 500, "Internal Server Error", "text/plain",
			  "out of memory\n");
		return;
	}
	if (run_scan(cfg, scan, SCAN_TEXT_MAX) < 0) {
		free(scan);
		render_page(fd, cfg, "扫描失败，请检查接口和内置引擎状态。", NULL);
		return;
	}
	render_page(fd, cfg, NULL, scan);
	free(scan);
}

static void handle_scan_text(int fd, const struct app_config *cfg)
{
	char *scan;

	scan = calloc(1, SCAN_TEXT_MAX);
	if (!scan) {
		http_send(fd, cfg, 500, "Internal Server Error", "text/plain",
			  "out of memory\n");
		return;
	}
	if (run_scan(cfg, scan, SCAN_TEXT_MAX) < 0) {
		free(scan);
		http_send(fd, cfg, 500, "Scan Failed", "text/plain", "scan failed\n");
		return;
	}
	http_send(fd, cfg, 200, "OK", "text/plain; charset=utf-8", scan);
	free(scan);
}

static void handle_client(int fd, const struct app_config *cfg)
{
	char *req;
	char method[8];
	char path[256];
	char *header_end;
	char *body;
	char *query;
	int total = 0;
	int need;
	int clen;

	log_msg(cfg, "http client begin fd=%d", fd);
	req = calloc(1, HTTP_REQ_MAX + 1);
	if (!req) {
		log_msg(cfg, "http client allocation failed");
		http_send(fd, cfg, 500, "Internal Server Error", "text/plain",
			  "out of memory\n");
		return;
	}

	while (total < HTTP_REQ_MAX) {
		ssize_t n = recv(fd, req + total, HTTP_REQ_MAX - total, 0);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			log_msg(cfg, "http recv failed errno=%d total=%d",
				errno, total);
			goto out;
		}
		if (n == 0) {
			log_msg(cfg, "http recv eof total=%d", total);
			break;
		}
		total += (int)n;
		log_msg(cfg, "http recv bytes=%ld total=%d", (long)n, total);
		req[total] = '\0';
		header_end = strstr(req, "\r\n\r\n");
		if (!header_end)
			continue;
		clen = content_length(req);
		if (clen < 0) {
			log_msg(cfg, "http invalid content length");
			http_send(fd, cfg, 400, "Bad Request",
				  "text/plain", "invalid content length\n");
			goto out;
		}
		if (clen > HTTP_BODY_MAX) {
			log_msg(cfg, "http payload too large content_length=%d",
				clen);
			http_send(fd, cfg, 413, "Payload Too Large",
				  "text/plain", "payload too large\n");
			goto out;
		}
		need = (int)(header_end + 4 - req) + clen;
		if (total >= need) {
			log_msg(cfg, "http headers complete total=%d body=%d",
				total, clen);
			break;
		}
	}

	req[total] = '\0';
	header_end = strstr(req, "\r\n\r\n");
	if (!header_end || sscanf(req, "%7s %255s", method, path) != 2) {
		log_msg(cfg, "http bad request total=%d", total);
		http_send(fd, cfg, 400, "Bad Request", "text/plain", "bad request\n");
		goto out;
	}
	clen = content_length(req);
	if (clen < 0) {
		log_msg(cfg, "http invalid content length after parse");
		http_send(fd, cfg, 400, "Bad Request",
			  "text/plain", "invalid content length\n");
		goto out;
	}
	need = (int)(header_end + 4 - req) + clen;
	if (clen > HTTP_BODY_MAX || need > HTTP_REQ_MAX || total < need) {
		log_msg(cfg, "http incomplete request total=%d need=%d body=%d",
			total, need, clen);
		http_send(fd, cfg, 400, "Bad Request", "text/plain", "incomplete request\n");
		goto out;
	}
	body = header_end + 4;
	query = strchr(path, '?');
	if (query)
		*query = '\0';

	log_msg(cfg, "http request method=%s path=%s body=%d",
		method, path, clen);

	if (strcmp(method, "GET") == 0 && strcmp(path, "/") == 0) {
		render_page(fd, cfg, NULL, NULL);
	} else if (strcmp(method, "GET") == 0 && strcmp(path, "/status") == 0) {
		render_status(fd, cfg);
	} else if (strcmp(method, "GET") == 0 && strcmp(path, "/scan") == 0) {
		handle_scan_text(fd, cfg);
	} else if (strcmp(method, "POST") == 0 &&
		   strcmp(path, "/scan") == 0) {
		handle_scan_page(fd, cfg);
	} else if (strcmp(method, "POST") == 0 &&
		   strcmp(path, "/connect") == 0) {
		handle_connect(fd, cfg, body);
	} else if (strcmp(method, "POST") == 0 &&
		   strcmp(path, "/disconnect") == 0) {
		stop_dhcp(cfg);
		stop_engine(cfg);
		deconfigure_iface(cfg);
		http_redirect(fd, cfg, "/");
	} else {
		http_send(fd, cfg, 404, "Not Found", "text/plain", "not found\n");
	}

out:
	log_msg(cfg, "http client end fd=%d", fd);
	free(req);
}

static int run_webui(const struct app_config *cfg)
{
	int s;
	int opt = 1;
	struct sockaddr_in addr;

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		perror("socket");
		return 1;
	}

	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons((unsigned short)cfg->port);

	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		close(s);
		return 1;
	}

	if (listen(s, 8) < 0) {
		perror("listen");
		close(s);
		return 1;
	}

	log_msg(cfg, "webui start port=%d iface=%s conf=%s dns=%s",
		cfg->port, cfg->iface, cfg->conf, cfg->dns_path);
	printf("wpa_mini WebUI listening on 0.0.0.0:%d\n", cfg->port);
	printf("interface=%s conf=%s dns=%s engine=internal\n",
	       cfg->iface, cfg->conf, cfg->dns_path);
	printf("log=%s\n", cfg->log_path);
	fflush(stdout);

	for (;;) {
		int c = accept(s, NULL, NULL);
		if (c < 0) {
			if (errno == EINTR)
				continue;
			perror("accept");
			log_msg(cfg, "accept failed errno=%d", errno);
			break;
		}
		log_msg(cfg, "accept ok fd=%d", c);
		handle_client(c, cfg);
		close(c);
		log_msg(cfg, "accept closed fd=%d", c);
		while (waitpid(-1, NULL, WNOHANG) > 0)
			;
	}

	close(s);
	return 1;
}

int main(int argc, char **argv)
{
	struct app_config cfg;
	const char *ssid = NULL;
	const char *psk = NULL;
	int foreground = 0;
	int dry_run = 0;
	int hidden = 0;
	int use_default_route = 0;
	int web = 0;
	int opt;

	cfg.iface = DEFAULT_IFACE;
	cfg.conf = DEFAULT_CONF;
	cfg.ctrl_dir = DEFAULT_CTRL;
	cfg.driver = DEFAULT_DRIVER;
	cfg.pidfile = DEFAULT_PIDFILE;
	cfg.dhcp_pidfile = DEFAULT_DHCP_PIDFILE;
	cfg.dhcp_script = DEFAULT_DHCP_SCRIPT;
	cfg.dns_path = DEFAULT_DNS_PATH;
	cfg.log_path = DEFAULT_LOG_PATH;
	cfg.udhcpc = DEFAULT_UDHCPC;
	cfg.port = DEFAULT_PORT;

	while ((opt = getopt(argc, argv, "wi:s:p:c:C:D:P:L:r:l:u:HMFnh")) != -1) {
		switch (opt) {
		case 'w':
			web = 1;
			break;
		case 'i':
			cfg.iface = optarg;
			break;
		case 's':
			ssid = optarg;
			break;
		case 'p':
			psk = optarg;
			break;
		case 'c':
			cfg.conf = optarg;
			break;
		case 'C':
			cfg.ctrl_dir = optarg;
			break;
		case 'D':
			cfg.driver = optarg;
			break;
		case 'P':
			cfg.pidfile = optarg;
			break;
		case 'L':
			cfg.port = atoi(optarg);
			break;
		case 'r':
			cfg.dns_path = optarg;
			break;
		case 'l':
			cfg.log_path = optarg;
			break;
		case 'u':
			cfg.udhcpc = optarg;
			break;
		case 'H':
			hidden = 1;
			break;
		case 'M':
			use_default_route = 1;
			break;
		case 'F':
			foreground = 1;
			break;
		case 'n':
			dry_run = 1;
			break;
		case 'h':
			usage(stdout);
			return 0;
		default:
			usage(stderr);
			return 2;
		}
	}

	install_signal_handlers(&cfg);
	log_msg(&cfg, "main start argc=%d iface=%s port=%d web=%d",
		argc, cfg.iface, cfg.port, web);

	if (cfg.port <= 0 || cfg.port > 65535) {
		fprintf(stderr, "invalid port\n");
		log_msg(&cfg, "invalid port=%d", cfg.port);
		return 2;
	}

	if (web || (!ssid && !psk && !dry_run))
		return run_webui(&cfg);

	if ((ssid && !psk) || (!ssid && psk)) {
		fprintf(stderr, "-s SSID and -p PSK must be used together\n");
		return 2;
	}

	if (!ssid || !psk) {
		fprintf(stderr, "missing -s SSID -p PSK for one-shot mode\n");
		usage(stderr);
		return 2;
	}

	if (write_config(cfg.conf, cfg.ctrl_dir, ssid, psk, "", hidden) < 0)
		return 1;
	log_msg(&cfg, "one-shot config written ssid=%s hidden=%d", ssid, hidden);

	if (dry_run) {
		printf("internal WPA engine: -D %s -i %s -c %s\n",
		       cfg.driver, cfg.iface, cfg.conf);
		printf("dns path: %s\n", cfg.dns_path);
		log_msg(&cfg, "dry-run complete");
		fflush(stdout);
		fflush(stderr);
		_exit(0);
	}

	stop_dhcp(&cfg);
	deconfigure_iface(&cfg);

	if (start_engine_process(&cfg) < 0) {
		fprintf(stderr, "failed to start internal WPA engine\n");
		log_msg(&cfg, "one-shot engine start failed");
		return 1;
	}

	if (wait_wpa_completed(&cfg, 20000) < 0) {
		fprintf(stderr, "warning: WPA state did not reach COMPLETED yet\n");
		log_msg(&cfg, "one-shot association timeout");
		stop_engine(&cfg);
		return 1;
	}

	if (start_dhcp(&cfg, DEFAULT_DNS1, DEFAULT_DNS2, use_default_route) < 0)
		fprintf(stderr, "warning: failed to start udhcpc\n");
	else if (wait_ipv4_ready(&cfg, 8000) < 0)
		fprintf(stderr, "warning: DHCP has not assigned an IP yet\n");

	log_msg(&cfg, "one-shot completed foreground=%d", foreground);
	if (foreground) {
		for (;;)
			pause();
	}

	fflush(stdout);
	fflush(stderr);
	_exit(0);
}
