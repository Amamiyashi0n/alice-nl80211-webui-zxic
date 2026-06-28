#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
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
#include <sys/statvfs.h>
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
#define SYSTEM_DNS_PATH "/etc_rw/resolv.conf"
#define DEFAULT_SAVED_PATH "/mnt/userdata/etc_rw/wpa_mini_saved.conf"
#define DEFAULT_RELAY_STATE "/tmp/wpa_mini_relay.state"
#define DEFAULT_LAN_ADJUST_STATE "/tmp/wpa_mini_lan_adjust.state"
#define DEFAULT_UDHCPD_CONF "/etc_rw/udhcpd.conf"
#define DEFAULT_UDHCPD_LEASES "/etc_rw/udhcpd.leases"
#define DEFAULT_RUN_PATH "/mnt/userdata/wpa_mini.run"
#define DEFAULT_AUTOSTART_SCRIPT "/mnt/userdata/wpa_mini_autostart.sh"
#define DEFAULT_AUTOSTART_RC "/etc/rc"
#define AUTOSTART_BEGIN "# wpa_mini autostart begin"
#define AUTOSTART_END "# wpa_mini autostart end"
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
#define SCAN_HTML_MAX 28000
#define SAVED_HTML_MAX 12000
#define AUTOSTART_HTML_MAX 6000
#define SYSTEM_HTML_MAX 42000
#define SYSTEM_TEXT_MAX 32768
#define PAGE_BODY_MAX 131072
#define SAVED_WIFI_MAX 8
#define SYS_IFACE_MAX 32
#define SYS_ROUTE_MAX 24
#define SYS_ARP_MAX 24
#define SYS_LISTEN_MAX 24
#define SYS_FS_MAX 8
#define RELAY_IFACES_TEXT_MAX 128

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
static void signal_dnsmasq_reload(const struct app_config *cfg);
static void stop_relay(const struct app_config *cfg);
static void set_cloexec(int fd);
static void close_inherited_fds(void);

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
	char sta_subnet[64];
	char lan_subnet[64];
	int default_route_ready;
	int sta_lan_conflict;
	int relay_enabled;
	char relay_lan_iface[IFNAMSIZ];
	char relay_lan_members[RELAY_IFACES_TEXT_MAX];
	char relay_lan_subnet[64];
	char relay_wan_iface[IFNAMSIZ];
	int relay_ip_forward;
	int relay_nat_rule;
	int relay_dhcp_running;
};

struct saved_wifi {
	char ssid[96];
	char psk[128];
	char dns1[64];
	char dns2[64];
	int hidden;
	int route;
	int relay;
};

struct autostart_status {
	int run_ready;
	int script_ready;
	int hook_ready;
};

struct sys_iface {
	char name[IFNAMSIZ];
	char kind[24];
	char mac[32];
	char ipv4[64];
	char ipv6[96];
	char state[64];
	char bridge[IFNAMSIZ];
	unsigned int flags;
	unsigned long mtu;
	unsigned long long rx_bytes;
	unsigned long long rx_packets;
	unsigned long long rx_errs;
	unsigned long long rx_drop;
	unsigned long long tx_bytes;
	unsigned long long tx_packets;
	unsigned long long tx_errs;
	unsigned long long tx_drop;
	int is_sta;
	int is_default;
	int has_wireless;
};

struct sys_route {
	char iface[IFNAMSIZ];
	char dest[64];
	char gateway[64];
	char mask[64];
	unsigned int flags;
	unsigned int metric;
	int is_default;
};

struct sys_arp {
	char ip[64];
	char mac[32];
	char flags[16];
	char iface[IFNAMSIZ];
};

struct sys_listen {
	char proto[16];
	char local[96];
	char state[32];
	char pidprog[96];
};

struct sys_fs {
	char path[64];
	char type[32];
	char opts[128];
	unsigned long total_kb;
	unsigned long avail_kb;
};

struct system_snapshot {
	char hostname[64];
	char kernel[192];
	char uptime[64];
	char loadavg[96];
	char mem[128];
	char dns_user[192];
	char dns_system[192];
	char default_iface[IFNAMSIZ];
	struct sys_iface ifaces[SYS_IFACE_MAX];
	int iface_count;
	struct sys_route routes[SYS_ROUTE_MAX];
	int route_count;
	struct sys_arp arps[SYS_ARP_MAX];
	int arp_count;
	struct sys_listen listens[SYS_LISTEN_MAX];
	int listen_count;
	struct sys_fs filesystems[SYS_FS_MAX];
	int fs_count;
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
		"  -N         enable WiFi relay/NAT from br0 to STA; implies -M\n"
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

static int write_config(const char *path, const char *ctrl_dir,
			const char *ssid, const char *psk, int hidden)
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
		close_inherited_fds();

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
		close_inherited_fds();

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

static void decode_escaped_ssid(char *out, size_t outsz, const char *in)
{
	size_t used = 0;

	if (!outsz)
		return;

	while (*in && used + 1 < outsz) {
		if (in[0] == '\\' && in[1] == 'x' &&
		    isxdigit((unsigned char)in[2]) &&
		    isxdigit((unsigned char)in[3])) {
			int hi = hex_value(in[2]);
			int lo = hex_value(in[3]);
			out[used++] = (char)((hi << 4) | lo);
			in += 4;
		} else {
			out[used++] = *in++;
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

static void url_encode(char *out, size_t outsz, const char *in)
{
	static const char hex[] = "0123456789ABCDEF";
	size_t used = 0;

	if (!outsz)
		return;

	while (*in && used + 1 < outsz) {
		unsigned char c = (unsigned char)*in++;

		if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
			out[used++] = (char)c;
		} else {
			if (used + 3 >= outsz)
				break;
			out[used++] = '%';
			out[used++] = hex[c >> 4];
			out[used++] = hex[c & 0x0f];
		}
	}
	out[used] = '\0';
}

static int load_saved_wifi(struct saved_wifi *items, int max_items)
{
	FILE *fp;
	char line[1024];
	int count = 0;

	fp = fopen(DEFAULT_SAVED_PATH, "r");
	if (!fp)
		return 0;

	while (count < max_items && fgets(line, sizeof(line), fp)) {
		struct saved_wifi item;
		char value[16];
		size_t len;
		int duplicate = 0;
		int i;

		memset(&item, 0, sizeof(item));
		len = strcspn(line, "\r\n");
		line[len] = '\0';
		if (!form_value(line, "ssid", item.ssid, sizeof(item.ssid)) ||
		    !form_value(line, "psk", item.psk, sizeof(item.psk)))
			continue;
		form_value(line, "dns1", item.dns1, sizeof(item.dns1));
		form_value(line, "dns2", item.dns2, sizeof(item.dns2));
		item.hidden = form_value(line, "hidden", value, sizeof(value)) &&
			      value[0] == '1';
		item.route = form_value(line, "route", value, sizeof(value)) ?
			     value[0] == '1' : 1;
		item.relay = form_value(line, "relay", value, sizeof(value)) &&
			     value[0] == '1';
		if (item.relay)
			item.route = 1;
		if (!valid_psk(item.psk) || !valid_ipv4_or_empty(item.dns1) ||
		    !valid_ipv4_or_empty(item.dns2))
			continue;
		for (i = 0; i < count; i++) {
			if (strcmp(items[i].ssid, item.ssid) == 0) {
				duplicate = 1;
				break;
			}
		}
		if (duplicate)
			continue;
		items[count++] = item;
	}

	fclose(fp);
	return count;
}

static int save_saved_wifi(const struct saved_wifi *items, int count)
{
	int fd;
	FILE *fp;
	int i;

	if (mkdir_parent(DEFAULT_SAVED_PATH) < 0)
		return -1;

	fd = open(DEFAULT_SAVED_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return -1;
	fp = fdopen(fd, "w");
	if (!fp) {
		close(fd);
		return -1;
	}

	for (i = 0; i < count; i++) {
		char ssid[288], psk[384], dns1[192], dns2[192];

		url_encode(ssid, sizeof(ssid), items[i].ssid);
		url_encode(psk, sizeof(psk), items[i].psk);
		url_encode(dns1, sizeof(dns1), items[i].dns1);
		url_encode(dns2, sizeof(dns2), items[i].dns2);
		fprintf(fp, "ssid=%s&psk=%s&dns1=%s&dns2=%s&hidden=%d&route=%d&relay=%d\n",
			ssid, psk, dns1, dns2, items[i].hidden ? 1 : 0,
			items[i].route ? 1 : 0, items[i].relay ? 1 : 0);
	}

	if (fclose(fp) != 0)
		return -1;
	chmod(DEFAULT_SAVED_PATH, 0600);
	return 0;
}

static void remember_wifi(const char *ssid, const char *psk,
			  const char *dns1,
			  const char *dns2, int hidden, int route, int relay)
{
	struct saved_wifi items[SAVED_WIFI_MAX];
	struct saved_wifi kept[SAVED_WIFI_MAX];
	struct saved_wifi next;
	int count;
	int i;
	int out = 0;

	memset(&next, 0, sizeof(next));
	snprintf(next.ssid, sizeof(next.ssid), "%s", ssid);
	snprintf(next.psk, sizeof(next.psk), "%s", psk);
	snprintf(next.dns1, sizeof(next.dns1), "%s", dns1 ? dns1 : DEFAULT_DNS1);
	snprintf(next.dns2, sizeof(next.dns2), "%s", dns2 ? dns2 : DEFAULT_DNS2);
	next.hidden = hidden ? 1 : 0;
	next.relay = relay ? 1 : 0;
	next.route = (route || relay) ? 1 : 0;

	count = load_saved_wifi(items, SAVED_WIFI_MAX);
	kept[out++] = next;
	for (i = 0; i < count; i++) {
		if (strcmp(items[i].ssid, next.ssid) == 0)
			continue;
		if (out < SAVED_WIFI_MAX)
			kept[out++] = items[i];
	}

	save_saved_wifi(kept, out);
}

static int forget_wifi(const char *ssid)
{
	struct saved_wifi items[SAVED_WIFI_MAX];
	struct saved_wifi kept[SAVED_WIFI_MAX];
	int count;
	int out = 0;
	int i;

	count = load_saved_wifi(items, SAVED_WIFI_MAX);
	for (i = 0; i < count; i++) {
		if (strcmp(items[i].ssid, ssid) == 0)
			continue;
		kept[out++] = items[i];
	}

	return save_saved_wifi(kept, out);
}

static char *read_file_alloc(const char *path, size_t maxsz, size_t *len_out)
{
	struct stat st;
	char *buf;
	int fd;
	size_t off = 0;

	if (len_out)
		*len_out = 0;
	if (stat(path, &st) < 0)
		return NULL;
	if (st.st_size < 0 || (size_t)st.st_size > maxsz) {
		errno = EFBIG;
		return NULL;
	}

	buf = malloc((size_t)st.st_size + 1);
	if (!buf) {
		errno = ENOMEM;
		return NULL;
	}
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		free(buf);
		return NULL;
	}
	while (off < (size_t)st.st_size) {
		ssize_t n = read(fd, buf + off, (size_t)st.st_size - off);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			close(fd);
			free(buf);
			return NULL;
		}
		if (n == 0)
			break;
		off += (size_t)n;
	}
	close(fd);
	buf[off] = '\0';
	if (len_out)
		*len_out = off;
	return buf;
}

static int file_contains(const char *path, const char *needle)
{
	char *buf;
	int found;

	buf = read_file_alloc(path, 128 * 1024, NULL);
	if (!buf)
		return 0;
	found = strstr(buf, needle) != NULL;
	free(buf);
	return found;
}

static void shell_quote(FILE *fp, const char *s)
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

static int write_all_fd(int fd, const char *buf, size_t len)
{
	while (len) {
		ssize_t n = write(fd, buf, len);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0) {
			errno = EIO;
			return -1;
		}
		buf += n;
		len -= (size_t)n;
	}
	return 0;
}

static void get_autostart_status(struct autostart_status *st)
{
	memset(st, 0, sizeof(*st));
	st->run_ready = access(DEFAULT_RUN_PATH, R_OK) == 0;
	st->script_ready = access(DEFAULT_AUTOSTART_SCRIPT, R_OK) == 0;
	st->hook_ready = file_contains(DEFAULT_AUTOSTART_RC, AUTOSTART_BEGIN) &&
			 file_contains(DEFAULT_AUTOSTART_RC, AUTOSTART_END);
}

static void remount_userdata_rw(void)
{
	system("mount -o remount,rw,exec /mnt/userdata 2>/dev/null || "
	       "mount -o remount,rw /mnt/userdata 2>/dev/null");
}

static int write_autostart_script(const struct app_config *cfg)
{
	int fd;
	FILE *fp;

	remount_userdata_rw();
	if (access(DEFAULT_RUN_PATH, R_OK) != 0) {
		errno = ENOENT;
		return -1;
	}
	if (mkdir_parent(DEFAULT_AUTOSTART_SCRIPT) < 0)
		return -1;

	fd = open(DEFAULT_AUTOSTART_SCRIPT,
		  O_WRONLY | O_CREAT | O_TRUNC, 0755);
	if (fd < 0)
		return -1;
	fp = fdopen(fd, "w");
	if (!fp) {
		close(fd);
		return -1;
	}

	fprintf(fp, "#!/bin/sh\n");
	fprintf(fp, "# generated by wpa_mini\n");
	fprintf(fp, "PATH=/sbin:/bin:/usr/sbin:/usr/bin\n");
	fprintf(fp, "mount -o remount,exec /tmp 2>/dev/null || true\n");
	fprintf(fp, "mount -o remount,rw,exec /mnt/userdata 2>/dev/null || mount -o remount,rw /mnt/userdata 2>/dev/null || true\n");
	fprintf(fp, "exec /bin/sh ");
	shell_quote(fp, DEFAULT_RUN_PATH);
	fprintf(fp, " -w -i ");
	shell_quote(fp, cfg->iface);
	fprintf(fp, " -L %d -c ", cfg->port);
	shell_quote(fp, cfg->conf);
	fprintf(fp, " -C ");
	shell_quote(fp, cfg->ctrl_dir);
	fprintf(fp, " -D ");
	shell_quote(fp, cfg->driver);
	fprintf(fp, " -P ");
	shell_quote(fp, cfg->pidfile);
	fprintf(fp, " -r ");
	shell_quote(fp, cfg->dns_path);
	fprintf(fp, " -l ");
	shell_quote(fp, cfg->log_path);
	fprintf(fp, " -u ");
	shell_quote(fp, cfg->udhcpc);
	fprintf(fp, "\n");

	if (fclose(fp) != 0)
		return -1;
	return chmod(DEFAULT_AUTOSTART_SCRIPT, 0755);
}

static void remount_root_rw(void)
{
	system("mount -o remount,rw / 2>/dev/null; "
	       "mount -o remount,rw /dev/root / 2>/dev/null");
}

static void remount_root_ro(void)
{
	system("sync; mount -o remount,ro / 2>/dev/null; "
	       "mount -o remount,ro /dev/root / 2>/dev/null");
}

static int install_autostart_hook(void)
{
	FILE *fp;
	int has_begin;
	int has_end;

	has_begin = file_contains(DEFAULT_AUTOSTART_RC, AUTOSTART_BEGIN);
	has_end = file_contains(DEFAULT_AUTOSTART_RC, AUTOSTART_END);
	if (has_begin && has_end)
		return 0;
	if (has_begin || has_end) {
		errno = EINVAL;
		return -1;
	}

	remount_root_rw();
	fp = fopen(DEFAULT_AUTOSTART_RC, "a");
	if (!fp) {
		remount_root_ro();
		return -1;
	}

	fprintf(fp, "\n%s\n", AUTOSTART_BEGIN);
	fprintf(fp, "if [ -f %s ]; then\n", DEFAULT_AUTOSTART_SCRIPT);
	fprintf(fp, "\t/bin/sh %s >/tmp/wpa_mini_autostart.out 2>/tmp/wpa_mini_autostart.err &\n",
		DEFAULT_AUTOSTART_SCRIPT);
	fprintf(fp, "fi\n");
	fprintf(fp, "%s\n", AUTOSTART_END);
	if (fclose(fp) != 0) {
		remount_root_ro();
		return -1;
	}
	sync();
	remount_root_ro();
	return 0;
}

static int remove_autostart_hook(void)
{
	char *buf;
	char *begin;
	char *end;
	char tmp_path[] = DEFAULT_AUTOSTART_RC ".wpa_mini_tmp";
	struct stat st;
	size_t len;
	int fd;
	int rc = -1;

	buf = read_file_alloc(DEFAULT_AUTOSTART_RC, 128 * 1024, &len);
	if (!buf)
		return file_contains(DEFAULT_AUTOSTART_RC, AUTOSTART_BEGIN) ? -1 : 0;
	begin = strstr(buf, AUTOSTART_BEGIN);
	if (!begin) {
		free(buf);
		return 0;
	}
	end = strstr(begin, AUTOSTART_END);
	if (!end) {
		free(buf);
		errno = EINVAL;
		return -1;
	}
	if (begin > buf && begin[-1] == '\n')
		begin--;
	end += strlen(AUTOSTART_END);
	if (*end == '\r')
		end++;
	if (*end == '\n')
		end++;

	remount_root_rw();
	fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0744);
	if (fd < 0)
		goto out;
	if (write_all_fd(fd, buf, (size_t)(begin - buf)) < 0)
		goto out_close;
	if (write_all_fd(fd, end, len - (size_t)(end - buf)) < 0)
		goto out_close;
	if (close(fd) < 0) {
		fd = -1;
		goto out;
	}
	fd = -1;
	if (stat(DEFAULT_AUTOSTART_RC, &st) == 0)
		chmod(tmp_path, st.st_mode & 0777);
	if (rename(tmp_path, DEFAULT_AUTOSTART_RC) < 0)
		goto out;
	sync();
	rc = 0;
	goto out;

out_close:
	close(fd);
	fd = -1;
out:
	if (fd >= 0)
		close(fd);
	unlink(tmp_path);
	remount_root_ro();
	free(buf);
	return rc;
}

static int disable_autostart(int *hook_remove_failed)
{
	int rc = 0;

	if (hook_remove_failed)
		*hook_remove_failed = 0;
	remount_userdata_rw();
	if (unlink(DEFAULT_AUTOSTART_SCRIPT) < 0 && errno != ENOENT)
		rc = -1;
	if (remove_autostart_hook() < 0) {
		rc = -1;
		if (hook_remove_failed)
			*hook_remove_failed = 1;
	}
	return rc;
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
		close_inherited_fds();
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
	char *argv[32];
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
		for (j = 0; args[j] && j < 30; j++)
			argv[j + 1] = args[j];
		argv[j + 1] = NULL;
		return run_quiet(argv);
	}

	if (access("/bin/busybox", X_OK) == 0) {
		argv[0] = "/bin/busybox";
		argv[1] = (char *)tool;
		for (j = 0; args[j] && j < 29; j++)
			argv[j + 2] = args[j];
		argv[j + 2] = NULL;
		return run_quiet(argv);
	}

	argv[0] = (char *)tool;
	for (j = 0; args[j] && j < 30; j++)
		argv[j + 1] = args[j];
	argv[j + 1] = NULL;
	return run_quiet(argv);
}

static void strip_newline(char *s);

static int command_output_contains(const char *cmd, const char *needle)
{
	FILE *fp;
	char line[512];
	int found = 0;

	fp = popen(cmd, "r");
	if (!fp)
		return 0;
	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, needle)) {
			found = 1;
			break;
		}
	}
	pclose(fp);
	return found;
}

static int read_int_file(const char *path, int fallback)
{
	FILE *fp;
	int value;

	fp = fopen(path, "r");
	if (!fp)
		return fallback;
	if (fscanf(fp, "%d", &value) != 1)
		value = fallback;
	fclose(fp);
	return value;
}

static int write_int_file(const char *path, int value)
{
	FILE *fp;
	int rc;

	fp = fopen(path, "w");
	if (!fp)
		return -1;
	rc = fprintf(fp, "%d\n", value) < 0 ? -1 : 0;
	if (fclose(fp) != 0)
		rc = -1;
	return rc;
}

static void set_cloexec(int fd)
{
	int flags;

	if (fd < 0)
		return;
	flags = fcntl(fd, F_GETFD);
	if (flags >= 0)
		fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

static void close_inherited_fds(void)
{
	long max_fd;
	int fd;

	max_fd = sysconf(_SC_OPEN_MAX);
	if (max_fd < 0 || max_fd > 256)
		max_fd = 256;
	for (fd = 3; fd < max_fd; fd++)
		close(fd);
}

static int read_iface_ipv4_net(const char *iface, struct in_addr *ip,
			       struct in_addr *mask)
{
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
		close(fd);
		return -1;
	}
	*ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFNETMASK, &ifr) < 0) {
		close(fd);
		return -1;
	}
	*mask = ((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr;
	close(fd);
	return 0;
}

static int mask_to_prefix(struct in_addr mask)
{
	uint32_t m = ntohl(mask.s_addr);
	int prefix = 0;

	while (m & 0x80000000U) {
		prefix++;
		m <<= 1;
	}
	return prefix;
}

static int iface_subnet_cidr(const char *iface, char *out, size_t outsz)
{
	struct in_addr ip;
	struct in_addr mask;
	struct in_addr net;
	char addr[INET_ADDRSTRLEN];

	if (read_iface_ipv4_net(iface, &ip, &mask) < 0)
		return -1;
	net.s_addr = ip.s_addr & mask.s_addr;
	if (!inet_ntop(AF_INET, &net, addr, sizeof(addr)))
		return -1;
	snprintf(out, outsz, "%s/%d", addr, mask_to_prefix(mask));
	return 0;
}

static int ifaces_same_subnet(const char *a, const char *b)
{
	struct in_addr ip_a;
	struct in_addr mask_a;
	struct in_addr ip_b;
	struct in_addr mask_b;

	if (read_iface_ipv4_net(a, &ip_a, &mask_a) < 0 ||
	    read_iface_ipv4_net(b, &ip_b, &mask_b) < 0)
		return 0;
	return (ip_a.s_addr & mask_a.s_addr) ==
	       (ip_b.s_addr & mask_b.s_addr) &&
	       mask_a.s_addr == mask_b.s_addr;
}

static int iface_has_default_route(const char *iface)
{
	FILE *fp;
	char line[256];
	int found = 0;

	fp = fopen("/proc/net/route", "r");
	if (!fp)
		return 0;
	if (!fgets(line, sizeof(line), fp)) {
		fclose(fp);
		return 0;
	}
	while (fgets(line, sizeof(line), fp)) {
		char ifn[IFNAMSIZ];
		unsigned long dest;
		unsigned long gw;
		unsigned int flags;

		if (sscanf(line, "%15s %lx %lx %x", ifn, &dest, &gw,
			   &flags) != 4)
			continue;
		if (strcmp(ifn, iface) == 0 && dest == 0 && (flags & 0x2)) {
			found = 1;
			break;
		}
	}
	fclose(fp);
	return found;
}

static int subnet_conflicts_addr(uint32_t net_host)
{
	DIR *dir;
	struct dirent *de;
	uint32_t mask = 0xffffff00U;

	dir = opendir("/sys/class/net");
	if (!dir)
		return 0;
	while ((de = readdir(dir)) != NULL) {
		struct in_addr ip;
		struct in_addr ifmask;
		uint32_t if_ip;
		uint32_t if_mask;
		uint32_t if_net;

		if (de->d_name[0] == '.')
			continue;
		if (read_iface_ipv4_net(de->d_name, &ip, &ifmask) < 0)
			continue;
		if_ip = ntohl(ip.s_addr);
		if_mask = ntohl(ifmask.s_addr);
		if (if_ip == 0 || if_mask == 0)
			continue;
		if_net = if_ip & if_mask;
		if ((net_host & if_mask) == if_net ||
		    (if_net & mask) == net_host) {
			closedir(dir);
			return 1;
		}
	}
	closedir(dir);
	return 0;
}

static int choose_lan_subnet(uint32_t *net_host_out)
{
	int i;

	for (i = 0; i <= 255; i++) {
		uint32_t candidate = 0xc0a80000U | ((uint32_t)i << 8);

		if (!subnet_conflicts_addr(candidate)) {
			*net_host_out = candidate;
			return 0;
		}
	}

	for (i = 16; i <= 31; i++) {
		uint32_t candidate = 0xac000000U | ((uint32_t)i << 16);

		if (!subnet_conflicts_addr(candidate)) {
			*net_host_out = candidate;
			return 0;
		}
	}
	return -1;
}

static void ipv4_from_host(uint32_t host, char *out, size_t outsz)
{
	struct in_addr a;

	a.s_addr = htonl(host);
	inet_ntop(AF_INET, &a, out, outsz);
}

static int write_udhcpd_conf(uint32_t net_host)
{
	FILE *fp;
	char ip_start[INET_ADDRSTRLEN];
	char ip_end[INET_ADDRSTRLEN];
	char ip_router[INET_ADDRSTRLEN];

	ipv4_from_host(net_host + 100, ip_start, sizeof(ip_start));
	ipv4_from_host(net_host + 200, ip_end, sizeof(ip_end));
	ipv4_from_host(net_host + 1, ip_router, sizeof(ip_router));
	if (mkdir_parent(DEFAULT_UDHCPD_CONF) < 0)
		return -1;
	fp = fopen(DEFAULT_UDHCPD_CONF, "w");
	if (!fp)
		return -1;
	fprintf(fp,
		"start %s\n"
		"end %s\n"
		"interface br0\n"
		"option subnet 255.255.255.0\n"
		"option dns %s\n"
		"option router %s\n"
		"option lease 86400\n"
		"pidfile /etc_rw/udhcpd.pid\n"
		"lease_file /etc_rw/udhcpd.leases\n",
		ip_start, ip_end, ip_router, ip_router);
	if (fclose(fp) != 0)
		return -1;
	unlink(DEFAULT_UDHCPD_LEASES);
	return 0;
}

static int start_udhcpd_process(void)
{
	const char *dirs[] = { "/sbin", "/bin", "/usr/sbin", "/usr/bin", NULL };
	char path[64];
	const char *exe = NULL;
	pid_t pid;
	int i;

	for (i = 0; dirs[i]; i++) {
		if (snprintf(path, sizeof(path), "%s/udhcpd", dirs[i]) < 0)
			continue;
		if (access(path, X_OK) == 0) {
			exe = path;
			break;
		}
	}
	if (!exe && access("/bin/busybox", X_OK) == 0)
		exe = "/bin/busybox";
	if (!exe) {
		errno = ENOENT;
		return -1;
	}

	pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		int fd;

		setsid();
		fd = open("/tmp/wpa_mini_udhcpd.out",
			  O_WRONLY | O_CREAT | O_APPEND, 0600);
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
		close_inherited_fds();
		if (strcmp(exe, "/bin/busybox") == 0)
			execl(exe, exe, "udhcpd", "-f", DEFAULT_UDHCPD_CONF,
			      (char *)NULL);
		else
			execl(exe, exe, "-f", DEFAULT_UDHCPD_CONF,
			      (char *)NULL);
		_exit(127);
	}
	return 0;
}

static int udhcpd_running(void)
{
	FILE *fp;
	char line[256];
	int found = 0;

	fp = popen("ps 2>/dev/null", "r");
	if (!fp)
		return 0;
	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, "udhcpd") && strstr(line, DEFAULT_UDHCPD_CONF)) {
			found = 1;
			break;
		}
	}
	pclose(fp);
	return found;
}

static void stop_udhcpd_process(void)
{
	FILE *fp;
	char line[256];

	fp = popen("ps 2>/dev/null", "r");
	if (!fp)
		return;
	while (fgets(line, sizeof(line), fp)) {
		long pid;
		char *end;

		if (!strstr(line, "udhcpd") || !strstr(line, DEFAULT_UDHCPD_CONF))
			continue;
		errno = 0;
		pid = strtol(line, &end, 10);
		if (pid > 1 && !errno)
			kill((pid_t)pid, SIGTERM);
	}
	pclose(fp);
	usleep(150000);
}

static int restart_udhcpd(void)
{
	stop_udhcpd_process();
	if (start_udhcpd_process() < 0)
		return -1;
	usleep(250000);
	return udhcpd_running() ? 0 : -1;
}

static int iface_net_host24(const char *iface, uint32_t *net_host)
{
	struct in_addr ip;
	struct in_addr mask;

	if (read_iface_ipv4_net(iface, &ip, &mask) < 0)
		return -1;
	if (mask_to_prefix(mask) != 24) {
		errno = EINVAL;
		return -1;
	}
	*net_host = ntohl(ip.s_addr & mask.s_addr);
	return 0;
}

static int ensure_lan_dhcp(const struct app_config *cfg, const char *lan_if)
{
	uint32_t net_host;

	if (iface_net_host24(lan_if, &net_host) < 0) {
		log_msg(cfg, "relay dhcp failed: %s is not a /24 lan errno=%d",
			lan_if, errno);
		return -1;
	}
	if (write_udhcpd_conf(net_host) < 0) {
		log_msg(cfg, "relay dhcp conf failed errno=%d", errno);
		return -1;
	}
	if (restart_udhcpd() < 0) {
		log_msg(cfg, "relay dhcp start failed errno=%d", errno);
		return -1;
	}
	log_msg(cfg, "relay dhcp ready lan=%s", lan_if);
	return 0;
}

static void bridge_members_text(const char *bridge, char *out, size_t outsz)
{
	DIR *dir;
	struct dirent *de;
	char path[PATH_MAX];

	if (outsz)
		out[0] = '\0';
	snprintf(path, sizeof(path), "/sys/class/net/%s/brif", bridge);
	dir = opendir(path);
	if (!dir)
		return;
	while ((de = readdir(dir)) != NULL) {
		if (de->d_name[0] == '.')
			continue;
		if (out[0])
			buf_append(out, outsz, ",");
		buf_append(out, outsz, "%s", de->d_name);
	}
	closedir(dir);
}

static void refresh_usb_bridge_members(const struct app_config *cfg,
				       const char *bridge)
{
	DIR *dir;
	struct dirent *de;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "/sys/class/net/%s/brif", bridge);
	dir = opendir(path);
	if (!dir)
		return;
	while ((de = readdir(dir)) != NULL) {
		char *down_args[] = { de->d_name, "down", NULL };
		char *up_args[] = { de->d_name, "up", NULL };

		if (de->d_name[0] == '.')
			continue;
		if (strncmp(de->d_name, "usb", 3) != 0 &&
		    strncmp(de->d_name, "usblan", 6) != 0)
			continue;
		log_msg(cfg, "lan adjust refreshing usb member=%s",
			de->d_name);
		run_tool_quiet("ifconfig", down_args);
		usleep(200000);
		run_tool_quiet("ifconfig", up_args);
	}
	closedir(dir);
}

static int adjust_lan_subnet(const struct app_config *cfg, uint32_t net_host,
			     char *new_subnet, size_t new_subnet_sz)
{
	char ip_router[INET_ADDRSTRLEN];
	char ip_bcast[INET_ADDRSTRLEN];
	char *ifconfig_args[] = { "br0", ip_router, "netmask", "255.255.255.0",
				  "broadcast", ip_bcast, "up", NULL };
	FILE *fp;

	ipv4_from_host(net_host + 1, ip_router, sizeof(ip_router));
	ipv4_from_host(net_host + 255, ip_bcast, sizeof(ip_bcast));
	log_msg(cfg, "lan adjust requested br0=%s/24", ip_router);

	stop_relay(cfg);
	if (write_udhcpd_conf(net_host) < 0) {
		log_msg(cfg, "lan adjust udhcpd conf failed errno=%d", errno);
		return -1;
	}
	if (run_tool_quiet("ifconfig", ifconfig_args) < 0) {
		log_msg(cfg, "lan adjust ifconfig failed errno=%d", errno);
		return -1;
	}
	if (restart_udhcpd() < 0) {
		log_msg(cfg, "lan adjust udhcpd restart failed errno=%d", errno);
		return -1;
	}
	refresh_usb_bridge_members(cfg, "br0");
	signal_dnsmasq_reload(cfg);
	fp = fopen(DEFAULT_LAN_ADJUST_STATE, "w");
	if (fp) {
		fprintf(fp, "br0=%s\nnet=%u\n", ip_router, net_host);
		fclose(fp);
	}
	snprintf(new_subnet, new_subnet_sz, "%s/24", ip_router);
	return 0;
}

static int iptables_rule(char *const args[])
{
	return run_tool_quiet("iptables", args);
}

static int relay_rule_exists(const char *chain, const char *src,
			     const char *in_if, const char *out_if,
			     int nat)
{
	char needle[256];

	if (nat) {
		snprintf(needle, sizeof(needle),
			 "-A %s -s %s -o %s -j MASQUERADE",
			 chain, src, out_if);
		return command_output_contains("iptables -t nat -S 2>/dev/null",
					       needle);
	}
	if (src && *src)
		snprintf(needle, sizeof(needle),
			 "-A %s -s %s -i %s -o %s -j ACCEPT",
			 chain, src, in_if, out_if);
	else
		snprintf(needle, sizeof(needle),
			 "-A %s -i %s -o %s -j ACCEPT", chain, in_if, out_if);
	return command_output_contains("iptables -S 2>/dev/null", needle);
}

static int add_relay_rule(const char *chain, const char *src,
			  const char *in_if, const char *out_if, int nat)
{
	char *nat_args[] = { "-t", "nat", "-A", (char *)chain,
			     "-s", (char *)src, "-o", (char *)out_if,
			     "-j", "MASQUERADE", NULL };
	char *fwd_src_args[] = { "-A", (char *)chain, "-s", (char *)src,
				 "-i", (char *)in_if, "-o", (char *)out_if,
				 "-j", "ACCEPT", NULL };
	char *fwd_args[] = { "-A", (char *)chain, "-i", (char *)in_if,
			     "-o", (char *)out_if, "-j", "ACCEPT", NULL };

	if (relay_rule_exists(chain, src, in_if, out_if, nat))
		return 0;
	if (nat)
		return iptables_rule(nat_args);
	return iptables_rule(src && *src ? fwd_src_args : fwd_args);
}

static int add_bridge_member_forward_rules(const char *bridge,
					   const char *subnet,
					   const char *wan_if)
{
	DIR *dir;
	struct dirent *de;
	char path[PATH_MAX];
	int ok = 1;

	snprintf(path, sizeof(path), "/sys/class/net/%s/brif", bridge);
	dir = opendir(path);
	if (!dir)
		return 1;
	while ((de = readdir(dir)) != NULL) {
		if (de->d_name[0] == '.')
			continue;
		if (add_relay_rule("FORWARD", subnet, de->d_name, wan_if, 0) < 0)
			ok = 0;
		if (add_relay_rule("FORWARD", "", wan_if, de->d_name, 0) < 0)
			ok = 0;
	}
	closedir(dir);
	return ok ? 0 : -1;
}

static void delete_relay_rule(const char *chain, const char *src,
			      const char *in_if, const char *out_if, int nat)
{
	char *nat_args[] = { "-t", "nat", "-D", (char *)chain,
			     "-s", (char *)src, "-o", (char *)out_if,
			     "-j", "MASQUERADE", NULL };
	char *fwd_src_args[] = { "-D", (char *)chain, "-s", (char *)src,
				 "-i", (char *)in_if, "-o", (char *)out_if,
				 "-j", "ACCEPT", NULL };
	char *fwd_args[] = { "-D", (char *)chain, "-i", (char *)in_if,
			     "-o", (char *)out_if, "-j", "ACCEPT", NULL };
	int i;

	for (i = 0; i < 8 && relay_rule_exists(chain, src, in_if, out_if, nat);
	     i++) {
		if (iptables_rule(nat ? nat_args :
				  (src && *src ? fwd_src_args : fwd_args)) < 0)
			break;
	}
}

static void delete_bridge_member_forward_rules(const char *bridge,
					       const char *subnet,
					       const char *wan_if)
{
	DIR *dir;
	struct dirent *de;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "/sys/class/net/%s/brif", bridge);
	dir = opendir(path);
	if (!dir)
		return;
	while ((de = readdir(dir)) != NULL) {
		if (de->d_name[0] == '.')
			continue;
		delete_relay_rule("FORWARD", subnet, de->d_name, wan_if, 0);
		delete_relay_rule("FORWARD", "", wan_if, de->d_name, 0);
	}
	closedir(dir);
}

static void signal_dnsmasq_reload(const struct app_config *cfg)
{
	FILE *fp;
	char line[256];

	fp = popen("ps | grep '[d]nsmasq' 2>/dev/null", "r");
	if (!fp)
		return;
	while (fgets(line, sizeof(line), fp)) {
		long pid;
		char *end;

		errno = 0;
		pid = strtol(line, &end, 10);
		if (pid > 1 && !errno) {
			log_msg(cfg, "relay dnsmasq hup pid=%ld", pid);
			kill((pid_t)pid, SIGHUP);
		}
	}
	pclose(fp);
}

static void sync_system_dns_for_relay(const struct app_config *cfg,
				      const char *dns1, const char *dns2)
{
	FILE *fp;
	const char *use_dns1 = (dns1 && *dns1) ? dns1 : DEFAULT_DNS1;
	const char *use_dns2 = (dns2 && *dns2) ? dns2 : DEFAULT_DNS2;

	if (strcmp(cfg->dns_path, SYSTEM_DNS_PATH) == 0 ||
	    strcmp(cfg->dns_path, "/etc/resolv.conf") == 0)
		goto reload;

	if (mkdir_parent(SYSTEM_DNS_PATH) < 0)
		return;
	fp = fopen(SYSTEM_DNS_PATH, "w");
	if (!fp) {
		log_msg(cfg, "relay system dns write failed errno=%d", errno);
		return;
	}
	if (use_dns1[0])
		fprintf(fp, "nameserver %s\n", use_dns1);
	if (use_dns2[0])
		fprintf(fp, "nameserver %s\n", use_dns2);
	if (fclose(fp) != 0)
		log_msg(cfg, "relay system dns close failed errno=%d", errno);

reload:
	signal_dnsmasq_reload(cfg);
}

static void relay_write_state(const char *lan_if, const char *subnet,
			      const char *wan_if, int old_forward,
			      int nat_rule, int fwd_rule)
{
	FILE *fp;

	if (mkdir_parent(DEFAULT_RELAY_STATE) < 0)
		return;
	fp = fopen(DEFAULT_RELAY_STATE, "w");
	if (!fp)
		return;
	fprintf(fp, "lan=%s\nsubnet=%s\nwan=%s\nold_forward=%d\nnat=%d\nfwd=%d\n",
		lan_if, subnet, wan_if, old_forward, nat_rule, fwd_rule);
	fclose(fp);
}

static int relay_read_state(char *lan_if, size_t lan_sz,
			    char *subnet, size_t subnet_sz,
			    char *wan_if, size_t wan_sz,
			    int *old_forward, int *nat_rule, int *fwd_rule)
{
	FILE *fp;
	char line[256];

	if (lan_sz)
		lan_if[0] = '\0';
	if (subnet_sz)
		subnet[0] = '\0';
	if (wan_sz)
		wan_if[0] = '\0';
	if (old_forward)
		*old_forward = -1;
	if (nat_rule)
		*nat_rule = 0;
	if (fwd_rule)
		*fwd_rule = 0;

	fp = fopen(DEFAULT_RELAY_STATE, "r");
	if (!fp)
		return -1;
	while (fgets(line, sizeof(line), fp)) {
		strip_newline(line);
		if (strncmp(line, "lan=", 4) == 0)
			snprintf(lan_if, lan_sz, "%s", line + 4);
		else if (strncmp(line, "subnet=", 7) == 0)
			snprintf(subnet, subnet_sz, "%s", line + 7);
		else if (strncmp(line, "wan=", 4) == 0)
			snprintf(wan_if, wan_sz, "%s", line + 4);
		else if (strncmp(line, "old_forward=", 12) == 0 && old_forward)
			*old_forward = atoi(line + 12);
		else if (strncmp(line, "nat=", 4) == 0 && nat_rule)
			*nat_rule = atoi(line + 4);
		else if (strncmp(line, "fwd=", 4) == 0 && fwd_rule)
			*fwd_rule = atoi(line + 4);
	}
	fclose(fp);
	return lan_if[0] && subnet[0] && wan_if[0] ? 0 : -1;
}

static void stop_relay(const struct app_config *cfg)
{
	char lan_if[IFNAMSIZ];
	char wan_if[IFNAMSIZ];
	char subnet[64];
	int old_forward;
	int nat_rule;
	int fwd_rule;

	if (relay_read_state(lan_if, sizeof(lan_if), subnet, sizeof(subnet),
			     wan_if, sizeof(wan_if), &old_forward, &nat_rule,
			     &fwd_rule) < 0)
		return;
	log_msg(cfg, "relay stop lan=%s subnet=%s wan=%s old_forward=%d nat=%d fwd=%d",
		lan_if, subnet, wan_if, old_forward, nat_rule, fwd_rule);
	if (nat_rule)
		delete_relay_rule("POSTROUTING", subnet, lan_if, wan_if, 1);
	if (fwd_rule) {
		delete_relay_rule("FORWARD", subnet, lan_if, wan_if, 0);
		delete_relay_rule("FORWARD", "", wan_if, lan_if, 0);
		delete_bridge_member_forward_rules(lan_if, subnet, wan_if);
	}
	if (old_forward == 0 || old_forward == 1)
		write_int_file("/proc/sys/net/ipv4/ip_forward", old_forward);
	unlink(DEFAULT_RELAY_STATE);
}

static int start_relay(const struct app_config *cfg, const char *dns1,
		       const char *dns2)
{
	const char *lan_if = "br0";
	char subnet[64];
	char adjusted_subnet[64];
	int old_forward;
	int nat_ok = 0;
	int fwd_ok = 0;

	if (ifaces_same_subnet(cfg->iface, lan_if)) {
		uint32_t net_host;

		log_msg(cfg, "relay subnet conflict detected: %s and %s share subnet",
			cfg->iface, lan_if);
		if (choose_lan_subnet(&net_host) < 0 ||
		    adjust_lan_subnet(cfg, net_host, adjusted_subnet,
				      sizeof(adjusted_subnet)) < 0) {
			log_msg(cfg, "relay lan auto adjust failed errno=%d", errno);
			errno = EINVAL;
			return -1;
		}
		log_msg(cfg, "relay lan auto adjusted subnet=%s",
			adjusted_subnet);
	}
	if (!iface_has_default_route(cfg->iface)) {
		log_msg(cfg, "relay start failed: no default route on %s",
			cfg->iface);
		errno = ENETUNREACH;
		return -1;
	}
	if (iface_subnet_cidr(lan_if, subnet, sizeof(subnet)) < 0) {
		log_msg(cfg, "relay start failed: no subnet for %s errno=%d",
			lan_if, errno);
		return -1;
	}
	if (ensure_lan_dhcp(cfg, lan_if) < 0)
		return -1;

	stop_relay(cfg);
	old_forward = read_int_file("/proc/sys/net/ipv4/ip_forward", 0);
	if (write_int_file("/proc/sys/net/ipv4/ip_forward", 1) < 0) {
		log_msg(cfg, "relay ip_forward enable failed errno=%d", errno);
		return -1;
	}

	if (add_relay_rule("POSTROUTING", subnet, lan_if, cfg->iface, 1) < 0) {
		log_msg(cfg, "relay nat rule failed subnet=%s wan=%s errno=%d",
			subnet, cfg->iface, errno);
		write_int_file("/proc/sys/net/ipv4/ip_forward", old_forward);
		return -1;
	}
	nat_ok = 1;
	if (add_relay_rule("FORWARD", subnet, lan_if, cfg->iface, 0) == 0 &&
	    add_relay_rule("FORWARD", "", cfg->iface, lan_if, 0) == 0 &&
	    add_bridge_member_forward_rules(lan_if, subnet, cfg->iface) == 0) {
		fwd_ok = 1;
	} else {
		log_msg(cfg, "relay forward rule warning errno=%d", errno);
		delete_relay_rule("FORWARD", subnet, lan_if, cfg->iface, 0);
		delete_relay_rule("FORWARD", "", cfg->iface, lan_if, 0);
		delete_bridge_member_forward_rules(lan_if, subnet, cfg->iface);
	}

	relay_write_state(lan_if, subnet, cfg->iface, old_forward, nat_ok,
			  fwd_ok);
	sync_system_dns_for_relay(cfg, dns1, dns2);
	log_msg(cfg, "relay started lan=%s subnet=%s wan=%s old_forward=%d fwd=%d",
		lan_if, subnet, cfg->iface, old_forward, fwd_ok);
	return 0;
}

static void get_relay_status(const struct app_config *cfg,
			     struct runtime_status *st)
{
	char lan_if[IFNAMSIZ];
	char wan_if[IFNAMSIZ];
	char subnet[64];
	int old_forward;
	int nat_rule;
	int fwd_rule;

	st->relay_ip_forward =
		read_int_file("/proc/sys/net/ipv4/ip_forward", 0);
	if (relay_read_state(lan_if, sizeof(lan_if), subnet, sizeof(subnet),
			     wan_if, sizeof(wan_if), &old_forward, &nat_rule,
			     &fwd_rule) < 0)
		return;
	snprintf(st->relay_lan_iface, sizeof(st->relay_lan_iface), "%s",
		 lan_if);
	bridge_members_text(lan_if, st->relay_lan_members,
			    sizeof(st->relay_lan_members));
	snprintf(st->relay_lan_subnet, sizeof(st->relay_lan_subnet), "%s",
		 subnet);
	snprintf(st->relay_wan_iface, sizeof(st->relay_wan_iface), "%s",
		 wan_if);
	st->relay_nat_rule =
		relay_rule_exists("POSTROUTING", subnet, lan_if, wan_if, 1);
	st->relay_dhcp_running = udhcpd_running();
	st->relay_enabled = st->engine_running &&
			    strcmp(st->wpa_state, "COMPLETED") == 0 &&
			    st->ip[0] &&
			    st->relay_ip_forward == 1 && st->relay_nat_rule &&
			    st->relay_dhcp_running &&
			    !st->sta_lan_conflict && st->default_route_ready;
	(void)cfg;
	(void)old_forward;
	(void)nat_rule;
	(void)fwd_rule;
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

static void read_dns_pair(const char *path, char *dns1, size_t dns1sz,
			  char *dns2, size_t dns2sz)
{
	FILE *fp;
	char line[256];
	int count = 0;

	if (dns1sz)
		dns1[0] = '\0';
	if (dns2sz)
		dns2[0] = '\0';
	fp = fopen(path, "r");
	if (!fp)
		return;
	while (fgets(line, sizeof(line), fp)) {
		char dns[64];

		if (sscanf(line, "nameserver %63s", dns) != 1)
			continue;
		if (!valid_ipv4_or_empty(dns))
			continue;
		if (count == 0)
			snprintf(dns1, dns1sz, "%s", dns);
		else if (count == 1) {
			snprintf(dns2, dns2sz, "%s", dns);
			break;
		}
		count++;
	}
	fclose(fp);
}

static void strip_newline(char *s)
{
	size_t len;

	if (!s)
		return;
	len = strlen(s);
	while (len && (s[len - 1] == '\n' || s[len - 1] == '\r'))
		s[--len] = '\0';
}

static char *trim_left(char *s)
{
	while (*s == ' ' || *s == '\t')
		s++;
	return s;
}

static const char *iface_kind(const char *name, int has_wireless)
{
	if (strcmp(name, "lo") == 0)
		return "Loopback";
	if (strncmp(name, "wan", 3) == 0)
		return "WAN";
	if (strncmp(name, "br", 2) == 0)
		return "Bridge";
	if (strncmp(name, "usb", 3) == 0 || strncmp(name, "usblan", 6) == 0)
		return "USB LAN";
	if (has_wireless || strncmp(name, "wlan", 4) == 0)
		return "WiFi";
	if (strncmp(name, "sit", 3) == 0 || strstr(name, "tnl"))
		return "Tunnel";
	return "Other";
}

static int read_text_first_line(const char *path, char *out, size_t outsz)
{
	FILE *fp;

	if (outsz)
		out[0] = '\0';
	fp = fopen(path, "r");
	if (!fp)
		return -1;
	if (!fgets(out, outsz, fp)) {
		fclose(fp);
		return -1;
	}
	fclose(fp);
	strip_newline(out);
	return 0;
}

static void format_uptime(char *out, size_t outsz)
{
	FILE *fp;
	double up = 0.0;
	unsigned long days;
	unsigned long hours;
	unsigned long mins;

	if (outsz)
		out[0] = '\0';
	fp = fopen("/proc/uptime", "r");
	if (!fp)
		return;
	if (fscanf(fp, "%lf", &up) != 1) {
		fclose(fp);
		return;
	}
	fclose(fp);
	days = (unsigned long)(up / 86400.0);
	hours = ((unsigned long)up % 86400UL) / 3600UL;
	mins = ((unsigned long)up % 3600UL) / 60UL;
	if (days)
		snprintf(out, outsz, "%lud %luh %lum", days, hours, mins);
	else
		snprintf(out, outsz, "%luh %lum", hours, mins);
}

static void read_mem_summary(char *out, size_t outsz)
{
	FILE *fp;
	char key[64];
	unsigned long value;
	char unit[32];
	unsigned long total = 0;
	unsigned long free_kb = 0;
	unsigned long cached = 0;
	unsigned long buffers = 0;

	if (outsz)
		out[0] = '\0';
	fp = fopen("/proc/meminfo", "r");
	if (!fp)
		return;
	while (fscanf(fp, "%63s %lu %31s", key, &value, unit) == 3) {
		if (strcmp(key, "MemTotal:") == 0)
			total = value;
		else if (strcmp(key, "MemFree:") == 0)
			free_kb = value;
		else if (strcmp(key, "Cached:") == 0)
			cached = value;
		else if (strcmp(key, "Buffers:") == 0)
			buffers = value;
	}
	fclose(fp);
	if (total)
		snprintf(out, outsz, "%luK total / %luK free / %luK cache",
			 total, free_kb, cached + buffers);
}

static int find_iface(struct system_snapshot *snap, const char *name)
{
	int i;

	for (i = 0; i < snap->iface_count; i++) {
		if (strcmp(snap->ifaces[i].name, name) == 0)
			return i;
	}
	return -1;
}

static struct sys_iface *ensure_iface(struct system_snapshot *snap,
				      const char *name)
{
	int idx;

	if (!name || !*name)
		return NULL;
	idx = find_iface(snap, name);
	if (idx >= 0)
		return &snap->ifaces[idx];
	if (snap->iface_count >= SYS_IFACE_MAX)
		return NULL;
	idx = snap->iface_count++;
	memset(&snap->ifaces[idx], 0, sizeof(snap->ifaces[idx]));
	snprintf(snap->ifaces[idx].name, sizeof(snap->ifaces[idx].name),
		 "%s", name);
	return &snap->ifaces[idx];
}

static void read_iface_ioctl(struct sys_iface *it)
{
	int fd;
	struct ifreq ifr;
	struct sockaddr_in *sin;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, it->name, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) == 0) {
		it->flags = (unsigned int)ifr.ifr_flags;
		if (ifr.ifr_flags & IFF_UP)
			buf_append(it->state, sizeof(it->state), "UP");
		else
			buf_append(it->state, sizeof(it->state), "DOWN");
		if (ifr.ifr_flags & IFF_RUNNING)
			buf_append(it->state, sizeof(it->state), " RUNNING");
	}
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, it->name, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
		unsigned char *a = (unsigned char *)ifr.ifr_hwaddr.sa_data;
		snprintf(it->mac, sizeof(it->mac),
			 "%02x:%02x:%02x:%02x:%02x:%02x",
			 a[0], a[1], a[2], a[3], a[4], a[5]);
	}
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, it->name, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFMTU, &ifr) == 0)
		it->mtu = (unsigned long)ifr.ifr_mtu;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, it->name, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
		sin = (struct sockaddr_in *)&ifr.ifr_addr;
		inet_ntop(AF_INET, &sin->sin_addr, it->ipv4, sizeof(it->ipv4));
	}
	close(fd);
	if (!it->state[0])
		snprintf(it->state, sizeof(it->state), "-");
}

static void read_iface_sysfs(struct sys_iface *it)
{
	char path[PATH_MAX];
	char tmp[96];
	char lower_state[64];
	size_t i;

	snprintf(path, sizeof(path), "/sys/class/net/%s/wireless", it->name);
	if (access(path, F_OK) == 0)
		it->has_wireless = 1;
	snprintf(path, sizeof(path), "/sys/class/net/%s/brport/bridge", it->name);
	{
		ssize_t n = readlink(path, tmp, sizeof(tmp) - 1);
		if (n > 0) {
			char *end;
			char *slash;
			tmp[n] = '\0';
			end = strrchr(tmp, '/');
			if (end && strcmp(end + 1, "bridge") == 0) {
				*end = '\0';
				end = strrchr(tmp, '/');
			}
			slash = end;
			snprintf(it->bridge, sizeof(it->bridge), "%s",
				 slash ? slash + 1 : tmp);
		}
	}
	snprintf(path, sizeof(path), "/sys/class/net/%s/operstate", it->name);
	if (read_text_first_line(path, tmp, sizeof(tmp)) == 0 && tmp[0] &&
	    strcmp(tmp, "unknown") != 0) {
		snprintf(lower_state, sizeof(lower_state), "%s", it->state);
		for (i = 0; lower_state[i]; i++)
			lower_state[i] = (char)tolower((unsigned char)lower_state[i]);
		if (strstr(lower_state, tmp))
			return;
		if (it->state[0])
			buf_append(it->state, sizeof(it->state), " ");
		buf_append(it->state, sizeof(it->state), "%s", tmp);
	}
}

static void read_ipv6_addrs(struct system_snapshot *snap)
{
	FILE *fp;
	char addr[40], iface[IFNAMSIZ];
	unsigned int idx, plen, scope, flags;

	fp = fopen("/proc/net/if_inet6", "r");
	if (!fp)
		return;
	while (fscanf(fp, "%32s %x %x %x %x %15s",
		      addr, &idx, &plen, &scope, &flags, iface) == 6) {
		struct sys_iface *it = ensure_iface(snap, iface);
		char pretty[96];
		if (!it || it->ipv6[0])
			continue;
		snprintf(pretty, sizeof(pretty),
			 "%.4s:%.4s:%.4s:%.4s:%.4s:%.4s:%.4s:%.4s/%u",
			 addr, addr + 4, addr + 8, addr + 12, addr + 16,
			 addr + 20, addr + 24, addr + 28, plen);
		snprintf(it->ipv6, sizeof(it->ipv6), "%s", pretty);
	}
	fclose(fp);
}

static void read_proc_net_dev(struct system_snapshot *snap)
{
	FILE *fp;
	char line[512];

	fp = fopen("/proc/net/dev", "r");
	if (!fp)
		return;
	if (!fgets(line, sizeof(line), fp) || !fgets(line, sizeof(line), fp)) {
		fclose(fp);
		return;
	}
	while (fgets(line, sizeof(line), fp)) {
		char *colon = strchr(line, ':');
		char *name;
		struct sys_iface *it;
		unsigned long long rx_fifo, rx_frame, rx_comp, rx_multi;
		unsigned long long tx_fifo, tx_colls, tx_carrier, tx_comp;

		if (!colon)
			continue;
		*colon = '\0';
		name = trim_left(line);
		strip_newline(name);
		it = ensure_iface(snap, name);
		if (!it)
			continue;
		sscanf(colon + 1,
		       "%llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
		       &it->rx_bytes, &it->rx_packets, &it->rx_errs,
		       &it->rx_drop, &rx_fifo, &rx_frame, &rx_comp, &rx_multi,
		       &it->tx_bytes, &it->tx_packets, &it->tx_errs,
		       &it->tx_drop, &tx_fifo, &tx_colls, &tx_carrier, &tx_comp);
	}
	fclose(fp);
}

static void read_bridge_members(struct system_snapshot *snap)
{
	DIR *dir;
	struct dirent *de;

	dir = opendir("/sys/class/net/br0/brif");
	if (!dir)
		return;
	while ((de = readdir(dir)) != NULL) {
		struct sys_iface *it;
		if (de->d_name[0] == '.')
			continue;
		it = ensure_iface(snap, de->d_name);
		if (it)
			snprintf(it->bridge, sizeof(it->bridge), "br0");
	}
	closedir(dir);
}

static void read_routes(struct system_snapshot *snap)
{
	FILE *fp;
	char line[256];

	fp = fopen("/proc/net/route", "r");
	if (!fp)
		return;
	fgets(line, sizeof(line), fp);
	while (fgets(line, sizeof(line), fp)) {
		char ifn[IFNAMSIZ];
		unsigned long dest, gw, mask;
		unsigned int flags, refcnt, use, metric, mtu, win, irtt;
		struct in_addr a;
		struct sys_route *rt;

		if (snap->route_count >= SYS_ROUTE_MAX)
			break;
		if (sscanf(line, "%15s %lx %lx %x %u %u %u %lx %u %u %u",
			   ifn, &dest, &gw, &flags, &refcnt, &use, &metric,
			   &mask, &mtu, &win, &irtt) != 11)
			continue;
		rt = &snap->routes[snap->route_count++];
		memset(rt, 0, sizeof(*rt));
		snprintf(rt->iface, sizeof(rt->iface), "%s", ifn);
		a.s_addr = (in_addr_t)dest;
		inet_ntop(AF_INET, &a, rt->dest, sizeof(rt->dest));
		a.s_addr = (in_addr_t)gw;
		inet_ntop(AF_INET, &a, rt->gateway, sizeof(rt->gateway));
		a.s_addr = (in_addr_t)mask;
		inet_ntop(AF_INET, &a, rt->mask, sizeof(rt->mask));
		rt->flags = flags;
		rt->metric = metric;
		rt->is_default = dest == 0;
		if (rt->is_default && !snap->default_iface[0])
			snprintf(snap->default_iface, sizeof(snap->default_iface),
				 "%s", ifn);
	}
	fclose(fp);
}

static void read_arps(struct system_snapshot *snap)
{
	FILE *fp;
	char line[256];

	fp = fopen("/proc/net/arp", "r");
	if (!fp)
		return;
	fgets(line, sizeof(line), fp);
	while (fgets(line, sizeof(line), fp)) {
		struct sys_arp *arp;
		char hwtype[16], mask[32];
		if (snap->arp_count >= SYS_ARP_MAX)
			break;
		arp = &snap->arps[snap->arp_count];
		if (sscanf(line, "%63s %15s %15s %31s %31s %15s",
			   arp->ip, hwtype, arp->flags, arp->mac, mask,
			   arp->iface) == 6)
			snap->arp_count++;
	}
	fclose(fp);
}

static void read_listeners(struct system_snapshot *snap)
{
	FILE *fp;
	char line[256];

	fp = popen("netstat -lntup 2>/dev/null", "r");
	if (!fp)
		return;
	while (fgets(line, sizeof(line), fp)) {
		struct sys_listen *ln;
		char recvq[32], sendq[32], foreign[96];
		char proto[16], local[96], state[32], pidprog[96];
		int fields;

		if (snap->listen_count >= SYS_LISTEN_MAX)
			break;
		if (strncmp(line, "tcp", 3) != 0 && strncmp(line, "udp", 3) != 0)
			continue;
		state[0] = '\0';
		pidprog[0] = '\0';
		fields = sscanf(line, "%15s %31s %31s %95s %95s %31s %95s",
				proto, recvq, sendq, local, foreign, state,
				pidprog);
		if (fields < 6)
			continue;
		ln = &snap->listens[snap->listen_count++];
		memset(ln, 0, sizeof(*ln));
		snprintf(ln->proto, sizeof(ln->proto), "%s", proto);
		snprintf(ln->local, sizeof(ln->local), "%s", local);
		if (strncmp(proto, "udp", 3) == 0 && fields == 6) {
			snprintf(ln->state, sizeof(ln->state), "-");
			snprintf(ln->pidprog, sizeof(ln->pidprog), "%s", state);
		} else {
			snprintf(ln->state, sizeof(ln->state), "%s", state);
			snprintf(ln->pidprog, sizeof(ln->pidprog), "%s",
				 fields >= 7 ? pidprog : "-");
		}
	}
	pclose(fp);
}

static void add_fs_usage(struct system_snapshot *snap, const char *path)
{
	FILE *fp;
	char line[512];
	struct statvfs sv;
	struct sys_fs *fs;

	if (snap->fs_count >= SYS_FS_MAX)
		return;
	fs = &snap->filesystems[snap->fs_count];
	memset(fs, 0, sizeof(*fs));
	snprintf(fs->path, sizeof(fs->path), "%s", path);
	fp = fopen("/proc/mounts", "r");
	if (fp) {
		while (fgets(line, sizeof(line), fp)) {
			char dev[128], mnt[128], type[32], opts[128];
			if (sscanf(line, "%127s %127s %31s %127s",
				   dev, mnt, type, opts) != 4)
				continue;
			if (strcmp(mnt, path) == 0) {
				snprintf(fs->type, sizeof(fs->type), "%s", type);
				snprintf(fs->opts, sizeof(fs->opts), "%s", opts);
				break;
			}
		}
		fclose(fp);
	}
	if (statvfs(path, &sv) == 0 && sv.f_frsize) {
		fs->total_kb = (unsigned long)((sv.f_blocks * sv.f_frsize) / 1024);
		fs->avail_kb = (unsigned long)((sv.f_bavail * sv.f_frsize) / 1024);
	}
	snap->fs_count++;
}

static void collect_system_snapshot(const struct app_config *cfg,
				    struct system_snapshot *snap)
{
	int i;

	memset(snap, 0, sizeof(*snap));
	read_text_first_line("/proc/sys/kernel/hostname", snap->hostname,
			     sizeof(snap->hostname));
	read_text_first_line("/proc/version", snap->kernel, sizeof(snap->kernel));
	read_text_first_line("/proc/loadavg", snap->loadavg, sizeof(snap->loadavg));
	format_uptime(snap->uptime, sizeof(snap->uptime));
	read_mem_summary(snap->mem, sizeof(snap->mem));
	read_dns_file(cfg->dns_path, snap->dns_user, sizeof(snap->dns_user));
	read_dns_file("/etc/resolv.conf", snap->dns_system,
		      sizeof(snap->dns_system));

	read_proc_net_dev(snap);
	read_ipv6_addrs(snap);
	read_bridge_members(snap);
	read_routes(snap);
	read_arps(snap);
	read_listeners(snap);
	add_fs_usage(snap, "/");
	add_fs_usage(snap, "/tmp");
	add_fs_usage(snap, "/mnt/userdata");
	add_fs_usage(snap, "/mnt/imagefs");
	add_fs_usage(snap, "/mnt/nvrofs");

	for (i = 0; i < snap->iface_count; i++) {
		struct sys_iface *it = &snap->ifaces[i];
		read_iface_ioctl(it);
		read_iface_sysfs(it);
		snprintf(it->kind, sizeof(it->kind), "%s",
			 iface_kind(it->name, it->has_wireless));
		it->is_sta = strcmp(it->name, cfg->iface) == 0;
		it->is_default = snap->default_iface[0] &&
				 strcmp(it->name, snap->default_iface) == 0;
	}
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
	if (iface_subnet_cidr(cfg->iface, st->sta_subnet,
			      sizeof(st->sta_subnet)) < 0)
		st->sta_subnet[0] = '\0';
	if (iface_subnet_cidr("br0", st->lan_subnet,
			      sizeof(st->lan_subnet)) < 0)
		st->lan_subnet[0] = '\0';
	st->default_route_ready = iface_has_default_route(cfg->iface);
	st->sta_lan_conflict = ifaces_same_subnet(cfg->iface, "br0");
	get_relay_status(cfg, st);
}

static int runtime_is_connected(const struct runtime_status *st)
{
	return strcmp(st->wpa_state, "COMPLETED") == 0 && st->ip[0];
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
		   "<th>SSID</th><th>信号</th><th>安全</th><th>BSSID</th><th>操作</th>"
		   "</tr></thead><tbody>");

	line = strtok_r(copy, "\n", &save);
	while ((line = strtok_r(NULL, "\n", &save)) != NULL) {
		char *fields[5];
		char *p = line;
		int i;
		char decoded_ssid[96];
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
		decode_escaped_ssid(decoded_ssid, sizeof(decoded_ssid), fields[4]);
		html_escape(esc_bssid, sizeof(esc_bssid), fields[0]);
		html_escape(esc_signal, sizeof(esc_signal), fields[2]);
		html_escape(esc_flags, sizeof(esc_flags), fields[3]);
		html_escape(esc_ssid, sizeof(esc_ssid), decoded_ssid);
		buf_append(out, outsz,
			   "<tr><td class=\"ssidcell\">%s</td><td>%s dBm</td><td>%s</td><td>%s</td>"
			   "<td><button class=\"pick\" type=\"button\" data-ssid=\"%s\" onclick=\"pickNet(this)\">选择</button></td></tr>",
			   esc_ssid, esc_signal, esc_flags, esc_bssid, esc_ssid);
		rows++;
	}

	if (!rows)
		buf_append(out, outsz, "<tr><td colspan=\"5\">未发现网络</td></tr>");
	buf_append(out, outsz, "</tbody></table></div></section>");
	free(copy);
}

static void build_saved_html(char *out, size_t outsz)
{
	struct saved_wifi items[SAVED_WIFI_MAX];
	int count;
	int i;

	if (outsz)
		out[0] = '\0';

	count = load_saved_wifi(items, SAVED_WIFI_MAX);
	buf_append(out, outsz,
		   "<section class=\"panel\"><div class=\"formtop\"><div>"
		   "<div class=\"title\">已保存 WiFi</div>"
		   "<div class=\"hint\">保存在 " DEFAULT_SAVED_PATH "，密码为明文</div>"
		   "</div></div><div class=\"pad\">");
	if (!count) {
		buf_append(out, outsz, "<div class=\"hint\">暂无保存的网络，连接成功后会自动保存。</div>");
	} else {
		for (i = 0; i < count; i++) {
			char esc_ssid[256], esc_dns1[128], esc_dns2[128];

			html_escape(esc_ssid, sizeof(esc_ssid), items[i].ssid);
			html_escape(esc_dns1, sizeof(esc_dns1), items[i].dns1);
			html_escape(esc_dns2, sizeof(esc_dns2), items[i].dns2);
			buf_append(out, outsz,
				   "<div class=\"saved\"><div><div class=\"v\">%s</div>"
				   "<div class=\"hint\">DNS %s / %s%s%s</div></div>"
				   "<div class=\"savedact\">"
				   "<form method=\"post\" action=\"/connect_saved\"><input type=\"hidden\" name=\"idx\" value=\"%d\"><button type=\"submit\">连接</button></form>"
				   "<form method=\"post\" action=\"/forget\"><input type=\"hidden\" name=\"ssid\" value=\"%s\"><button class=\"alt\" type=\"submit\">删除</button></form>"
				   "</div></div>",
				   esc_ssid,
				   esc_dns1[0] ? esc_dns1 : DEFAULT_DNS1,
				   esc_dns2[0] ? esc_dns2 : DEFAULT_DNS2,
				   items[i].hidden ? " · 隐藏" : "",
				   items[i].relay ? " · 中继" : "",
				   i, esc_ssid);
		}
	}
	buf_append(out, outsz, "</div></section>");
}

static void build_autostart_html(char *out, size_t outsz)
{
	struct autostart_status st;
	const char *label;
	const char *detail;

	if (outsz)
		out[0] = '\0';

	get_autostart_status(&st);
	if (st.run_ready && st.script_ready && st.hook_ready) {
		label = "已启用";
		detail = "开机会从 /mnt/userdata 启动 WebUI";
	} else if (st.script_ready || st.hook_ready) {
		label = "部分启用";
		detail = "启动脚本或系统钩子不完整，可重新启用修复";
	} else {
		label = "未启用";
		detail = st.run_ready ? "可写入开机启动项" :
			 "缺少 /mnt/userdata/wpa_mini.run";
	}

	buf_append(out, outsz,
		   "<section class=\"panel\"><div class=\"formtop\"><div>"
		   "<div class=\"title\">开机自启动</div>"
		   "<div class=\"hint\">启动包：" DEFAULT_RUN_PATH "</div>"
		   "</div></div><div class=\"pad\"><div class=\"grid\">"
		   "<div class=\"kv\"><div class=\"k\">状态</div><div class=\"v\">%s</div></div>"
		   "<div class=\"kv\"><div class=\"k\">说明</div><div class=\"v\">%s</div></div>"
		   "<div class=\"kv\"><div class=\"k\">启动脚本</div><div class=\"v\">%s</div></div>"
		   "<div class=\"kv\"><div class=\"k\">系统钩子</div><div class=\"v\">%s</div></div>"
		   "</div><div class=\"actions\">"
		   "<form method=\"post\" action=\"/autostart_on\"><button type=\"submit\">启用自启动</button></form>"
		   "<form method=\"post\" action=\"/autostart_off\"><button class=\"alt\" type=\"submit\">关闭自启动</button></form>"
		   "</div></div></section>",
		   label, detail,
		   st.script_ready ? "已写入" : "未写入",
		   st.hook_ready ? "已安装" : "未安装");
}

static void append_system_overview_html(const struct system_snapshot *snap,
					char *out, size_t outsz)
{
	char esc[512], esc2[512], esc3[512], esc4[512], esc5[512];

	html_escape(esc, sizeof(esc), snap->hostname[0] ? snap->hostname : "-");
	html_escape(esc2, sizeof(esc2), snap->uptime[0] ? snap->uptime : "-");
	html_escape(esc3, sizeof(esc3), snap->loadavg[0] ? snap->loadavg : "-");
	html_escape(esc4, sizeof(esc4), snap->default_iface[0] ?
		    snap->default_iface : "-");
	html_escape(esc5, sizeof(esc5), snap->mem[0] ? snap->mem : "-");
	buf_append(out, outsz,
		   "<section class=\"panel\"><div class=\"formtop\"><div>"
		   "<div class=\"title\">系统概览</div>"
		   "<div class=\"hint\">只读信息，来自 /proc 和系统配置文件</div>"
		   "</div><a class=\"tinylink\" href=\"/system\">文本快照</a>"
		   "</div><div class=\"pad\"><div class=\"grid\">"
		   "<div class=\"kv\"><div class=\"k\">主机名</div><div class=\"v\">%s</div></div>"
		   "<div class=\"kv\"><div class=\"k\">运行时间</div><div class=\"v\">%s</div></div>"
		   "<div class=\"kv\"><div class=\"k\">负载</div><div class=\"v\">%s</div></div>"
		   "<div class=\"kv\"><div class=\"k\">默认路由接口</div><div class=\"v\">%s</div></div>"
		   "<div class=\"kv\"><div class=\"k\">内存</div><div class=\"v\">%s</div></div>",
		   esc, esc2, esc3, esc4, esc5);
	html_escape(esc, sizeof(esc), snap->dns_user[0] ? snap->dns_user : "-");
	html_escape(esc2, sizeof(esc2), snap->dns_system[0] ?
		    snap->dns_system : "-");
	buf_append(out, outsz,
		   "<div class=\"kv\"><div class=\"k\">wpa_mini DNS</div><div class=\"v\">%s</div></div>"
		   "<div class=\"kv\"><div class=\"k\">系统 DNS</div><div class=\"v\">%s</div></div>",
		   esc, esc2);
	html_escape(esc, sizeof(esc), snap->kernel[0] ? snap->kernel : "-");
	buf_append(out, outsz,
		   "<div class=\"kv wide\"><div class=\"k\">内核</div><div class=\"v smallv\">%s</div></div>"
		   "</div></div></section>",
		   esc);
}

static void append_interfaces_html(const struct system_snapshot *snap,
				   char *out, size_t outsz)
{
	char esc[512], esc2[512], esc3[512], esc4[512], esc5[512];
	int i;

	buf_append(out, outsz,
		   "<section class=\"panel\"><div class=\"formtop\"><div>"
		   "<div class=\"title\">网络接口</div>"
		   "<div class=\"hint\">列出目标系统发现的全部接口，STA 和默认路由会自动标记</div>"
		   "</div><a class=\"tinylink\" href=\"/interfaces\">刷新</a>"
		   "</div><div class=\"tablewrap\"><table><thead><tr>"
		   "<th>接口</th><th>类型</th><th>状态</th><th>IPv4</th><th>IPv6</th><th>MAC</th><th>MTU</th><th>Bridge</th><th>RX/TX</th><th>错误/丢包</th>"
		   "</tr></thead><tbody>");
	for (i = 0; i < snap->iface_count; i++) {
		const struct sys_iface *it = &snap->ifaces[i];
		char rowcls[64] = "";
		char rx_tx[128];
		char errs[128];
		char mtu[32];

		if (it->is_sta)
			snprintf(rowcls, sizeof(rowcls), " class=\"focusrow\"");
		else if (it->is_default)
			snprintf(rowcls, sizeof(rowcls), " class=\"defrow\"");
		snprintf(rx_tx, sizeof(rx_tx), "%llu/%llu B",
			 it->rx_bytes, it->tx_bytes);
		snprintf(errs, sizeof(errs), "rx %llu/%llu · tx %llu/%llu",
			 it->rx_errs, it->rx_drop, it->tx_errs, it->tx_drop);
		snprintf(mtu, sizeof(mtu), "%lu", it->mtu);
		html_escape(esc, sizeof(esc), it->name);
		html_escape(esc2, sizeof(esc2), it->kind[0] ? it->kind : "-");
		html_escape(esc3, sizeof(esc3), it->state[0] ? it->state : "-");
		html_escape(esc4, sizeof(esc4), it->ipv4[0] ? it->ipv4 : "-");
		html_escape(esc5, sizeof(esc5), it->ipv6[0] ? it->ipv6 : "-");
		buf_append(out, outsz,
			   "<tr%s><td class=\"ssidcell\">%s%s%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>",
			   rowcls, esc,
			   it->is_sta ? " <span class=\"tag\">STA</span>" : "",
			   it->is_default ? " <span class=\"tag\">默认</span>" : "",
			   esc2, esc3, esc4, esc5);
		html_escape(esc, sizeof(esc), it->mac[0] ? it->mac : "-");
		html_escape(esc2, sizeof(esc2), mtu);
		html_escape(esc3, sizeof(esc3), it->bridge[0] ? it->bridge : "-");
		html_escape(esc4, sizeof(esc4), rx_tx);
		html_escape(esc5, sizeof(esc5), errs);
		buf_append(out, outsz,
			   "<td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
			   esc, esc2, esc3, esc4, esc5);
	}
	if (!snap->iface_count)
		buf_append(out, outsz, "<tr><td colspan=\"10\">未读取到接口</td></tr>");
	buf_append(out, outsz, "</tbody></table></div></section>");
}

static void append_routes_arp_html(const struct system_snapshot *snap,
				   char *out, size_t outsz)
{
	char esc[512], esc2[512], esc3[512], esc4[512];
	int i;

	buf_append(out, outsz,
		   "<section class=\"panel\"><div class=\"formtop\"><div>"
		   "<div class=\"title\">路由与邻居</div>"
		   "<div class=\"hint\">IPv4 路由表和 ARP 表</div>"
		   "</div></div><div class=\"tablewrap\"><table><thead><tr>"
		   "<th>目标</th><th>网关</th><th>掩码</th><th>接口</th><th>Metric</th><th>标记</th>"
		   "</tr></thead><tbody>");
	for (i = 0; i < snap->route_count; i++) {
		const struct sys_route *rt = &snap->routes[i];
		html_escape(esc, sizeof(esc), rt->dest);
		html_escape(esc2, sizeof(esc2), rt->gateway);
		html_escape(esc3, sizeof(esc3), rt->mask);
		html_escape(esc4, sizeof(esc4), rt->iface);
		buf_append(out, outsz,
			   "<tr%s><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%u</td><td>0x%x%s</td></tr>",
			   rt->is_default ? " class=\"defrow\"" : "",
			   esc, esc2, esc3, esc4, rt->metric, rt->flags,
			   rt->is_default ? " 默认" : "");
	}
	if (!snap->route_count)
		buf_append(out, outsz, "<tr><td colspan=\"6\">无 IPv4 路由</td></tr>");
	buf_append(out, outsz, "</tbody></table></div><div class=\"tablewrap\"><table><thead><tr>"
		   "<th>IP</th><th>MAC</th><th>接口</th><th>标记</th>"
		   "</tr></thead><tbody>");
	for (i = 0; i < snap->arp_count; i++) {
		const struct sys_arp *arp = &snap->arps[i];
		html_escape(esc, sizeof(esc), arp->ip);
		html_escape(esc2, sizeof(esc2), arp->mac);
		html_escape(esc3, sizeof(esc3), arp->iface);
		html_escape(esc4, sizeof(esc4), arp->flags);
		buf_append(out, outsz,
			   "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
			   esc, esc2, esc3, esc4);
	}
	if (!snap->arp_count)
		buf_append(out, outsz, "<tr><td colspan=\"4\">无 ARP 记录</td></tr>");
	buf_append(out, outsz, "</tbody></table></div></section>");
}

static void append_services_mounts_html(const struct system_snapshot *snap,
					char *out, size_t outsz)
{
	char esc[512], esc2[512], esc3[512], esc4[512];
	int i;

	buf_append(out, outsz,
		   "<section class=\"panel\"><div class=\"formtop\"><div>"
		   "<div class=\"title\">监听服务</div>"
		   "<div class=\"hint\">当前开放端口，只做读取展示</div>"
		   "</div></div><div class=\"tablewrap\"><table><thead><tr>"
		   "<th>协议</th><th>监听地址</th><th>状态</th><th>进程</th>"
		   "</tr></thead><tbody>");
	for (i = 0; i < snap->listen_count; i++) {
		const struct sys_listen *ln = &snap->listens[i];
		html_escape(esc, sizeof(esc), ln->proto);
		html_escape(esc2, sizeof(esc2), ln->local);
		html_escape(esc3, sizeof(esc3), ln->state);
		html_escape(esc4, sizeof(esc4), ln->pidprog);
		buf_append(out, outsz,
			   "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
			   esc, esc2, esc3, esc4);
	}
	if (!snap->listen_count)
		buf_append(out, outsz, "<tr><td colspan=\"4\">未读取到监听端口</td></tr>");
	buf_append(out, outsz, "</tbody></table></div></section>"
		   "<section class=\"panel\"><div class=\"formtop\"><div>"
		   "<div class=\"title\">挂载分区</div>"
		   "<div class=\"hint\">关键分区容量和挂载选项</div>"
		   "</div></div><div class=\"tablewrap\"><table><thead><tr>"
		   "<th>挂载点</th><th>类型</th><th>可用/总量</th><th>选项</th>"
		   "</tr></thead><tbody>");
	for (i = 0; i < snap->fs_count; i++) {
		const struct sys_fs *fs = &snap->filesystems[i];
		char usage[96];
		snprintf(usage, sizeof(usage), "%luK / %luK",
			 fs->avail_kb, fs->total_kb);
		html_escape(esc, sizeof(esc), fs->path);
		html_escape(esc2, sizeof(esc2), fs->type[0] ? fs->type : "-");
		html_escape(esc3, sizeof(esc3), usage);
		html_escape(esc4, sizeof(esc4), fs->opts[0] ? fs->opts : "-");
		buf_append(out, outsz,
			   "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
			   esc, esc2, esc3, esc4);
	}
	if (!snap->fs_count)
		buf_append(out, outsz, "<tr><td colspan=\"4\">未读取到挂载信息</td></tr>");
	buf_append(out, outsz, "</tbody></table></div></section>");
}

static void build_interfaces_html(const struct app_config *cfg, char *out,
				  size_t outsz)
{
	struct system_snapshot snap;

	if (outsz)
		out[0] = '\0';
	collect_system_snapshot(cfg, &snap);
	append_interfaces_html(&snap, out, outsz);
	append_routes_arp_html(&snap, out, outsz);
}

static void build_system_page_html(const struct app_config *cfg, char *out,
				   size_t outsz)
{
	struct system_snapshot snap;

	if (outsz)
		out[0] = '\0';
	collect_system_snapshot(cfg, &snap);
	append_system_overview_html(&snap, out, outsz);
	append_services_mounts_html(&snap, out, outsz);
}

static void build_system_text(const struct app_config *cfg, char *out,
			      size_t outsz)
{
	struct system_snapshot snap;
	int i;

	if (outsz)
		out[0] = '\0';
	collect_system_snapshot(cfg, &snap);
	buf_append(out, outsz, "hostname=%s\n", snap.hostname);
	buf_append(out, outsz, "kernel=%s\n", snap.kernel);
	buf_append(out, outsz, "uptime=%s\n", snap.uptime);
	buf_append(out, outsz, "loadavg=%s\n", snap.loadavg);
	buf_append(out, outsz, "memory=%s\n", snap.mem);
	buf_append(out, outsz, "default_iface=%s\n", snap.default_iface);
	buf_append(out, outsz, "dns_user=%s\n", snap.dns_user);
	buf_append(out, outsz, "dns_system=%s\n\n", snap.dns_system);

	buf_append(out, outsz, "[interfaces]\n");
	for (i = 0; i < snap.iface_count; i++) {
		struct sys_iface *it = &snap.ifaces[i];
		buf_append(out, outsz,
			   "%s kind=%s state=%s ipv4=%s ipv6=%s mac=%s mtu=%lu bridge=%s rx=%llu/%llu tx=%llu/%llu errdrop=%llu/%llu/%llu/%llu%s%s\n",
			   it->name, it->kind, it->state, it->ipv4, it->ipv6,
			   it->mac, it->mtu, it->bridge,
			   it->rx_bytes, it->rx_packets,
			   it->tx_bytes, it->tx_packets,
			   it->rx_errs, it->rx_drop, it->tx_errs, it->tx_drop,
			   it->is_sta ? " sta" : "",
			   it->is_default ? " default" : "");
	}
	buf_append(out, outsz, "\n[routes]\n");
	for (i = 0; i < snap.route_count; i++) {
		struct sys_route *rt = &snap.routes[i];
		buf_append(out, outsz,
			   "%s dest=%s gateway=%s mask=%s flags=0x%x metric=%u%s\n",
			   rt->iface, rt->dest, rt->gateway, rt->mask,
			   rt->flags, rt->metric,
			   rt->is_default ? " default" : "");
	}
	buf_append(out, outsz, "\n[arp]\n");
	for (i = 0; i < snap.arp_count; i++) {
		struct sys_arp *arp = &snap.arps[i];
		buf_append(out, outsz, "%s mac=%s iface=%s flags=%s\n",
			   arp->ip, arp->mac, arp->iface, arp->flags);
	}
	buf_append(out, outsz, "\n[listeners]\n");
	for (i = 0; i < snap.listen_count; i++) {
		struct sys_listen *ln = &snap.listens[i];
		buf_append(out, outsz, "%s %s %s %s\n",
			   ln->proto, ln->local, ln->state, ln->pidprog);
	}
	buf_append(out, outsz, "\n[filesystems]\n");
	for (i = 0; i < snap.fs_count; i++) {
		struct sys_fs *fs = &snap.filesystems[i];
		buf_append(out, outsz, "%s type=%s avail=%luK total=%luK opts=%s\n",
			   fs->path, fs->type, fs->avail_kb, fs->total_kb,
			   fs->opts);
	}
}

enum web_page {
	WEB_PAGE_HOME,
	WEB_PAGE_INTERFACES,
	WEB_PAGE_SYSTEM
};

static const char *nav_active(enum web_page current, enum web_page item)
{
	return current == item ? "active" : "";
}

static void append_page_start(char *body, size_t bodysz,
			      const struct app_config *cfg,
			      const struct runtime_status *st,
			      enum web_page page, const char *title,
			      const char *subtitle, const char *message)
{
	char esc_title[128], esc_subtitle[256], esc_msg[512];
	char esc_iface[128], esc_state[128], esc_ssid[256], esc_ip[128];
	const char *state_color;
	const char *state_label;

	html_escape(esc_title, sizeof(esc_title), title ? title : "WPA Mini");
	html_escape(esc_subtitle, sizeof(esc_subtitle), subtitle ? subtitle : "");
	html_escape(esc_msg, sizeof(esc_msg), message ? message : "");
	html_escape(esc_iface, sizeof(esc_iface), cfg->iface);
	html_escape(esc_state, sizeof(esc_state), st->wpa_state);
	html_escape(esc_ssid, sizeof(esc_ssid), st->ssid);
	html_escape(esc_ip, sizeof(esc_ip), st->ip);
	state_color = strcmp(st->wpa_state, "COMPLETED") == 0 ? "#2f7d4f" :
		      st->engine_running ? "#936b20" : "#9b4444";
	state_label = strcmp(st->wpa_state, "COMPLETED") == 0 ? "已连接" :
		      st->engine_running ? "连接中" : "已停止";

	buf_append(body, bodysz,
		   "<!doctype html><html><head><meta charset=\"utf-8\">"
		   "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
		   "<title>%s - WPA Mini</title>"
		   "<style>"
		   "*{box-sizing:border-box}body{margin:0;font-family:Arial,'Microsoft YaHei',sans-serif;background:#f4f8f2;color:#18251d}"
		   "a{color:inherit;text-decoration:none}"
		   "@keyframes rise{from{opacity:.62;transform:translateY(7px)}to{opacity:1;transform:none}}"
		   "@keyframes pulse{0%%{box-shadow:0 0 0 0 rgba(47,125,79,.28)}100%%{box-shadow:0 0 0 14px rgba(47,125,79,0)}}"
		   ".shell{min-height:100vh;display:grid;grid-template-columns:218px minmax(0,1fr)}"
		   ".side{position:sticky;top:0;height:100vh;background:#fbfdf9;border-right:1px solid #dbe8dc;padding:18px 14px;display:flex;flex-direction:column;gap:16px}"
		   ".brandbox{padding:4px 4px 10px}"
		   ".brand{font-size:19px;font-weight:800}.sub,.hint{font-size:12px;color:#67786b;margin-top:3px;line-height:1.45}"
		   ".nav{display:flex;flex-direction:column;gap:6px}.nav a{border-radius:8px;padding:10px 11px;color:#405246;font-size:14px;font-weight:700;transition:background .15s,color .15s,transform .15s}.nav a:hover{background:#eef7ef;transform:translateX(2px)}.nav a.active{background:#dcefe2;color:#1e5e3a}"
		   ".sidecard{margin-top:auto;border:1px solid #dbe8dc;border-radius:8px;background:#fff;padding:12px}.pill{display:inline-block;border-radius:999px;padding:6px 10px;background:%s;color:#fff;font-size:13px;font-weight:800;white-space:nowrap}"
		   "main.page{min-width:0;max-width:1160px;width:100%%;margin:0 auto;padding:22px 22px 30px}.topline{display:flex;justify-content:space-between;align-items:flex-start;gap:14px;margin-bottom:16px}.h1{font-size:25px;font-weight:800;letter-spacing:0}.topmeta{text-align:right;min-width:128px}"
		   ".msg{background:#eef8f0;border:1px solid #c9dfd0;border-radius:8px;color:#235a39;padding:12px 14px;margin-bottom:14px;animation:rise .18s ease-out}.summary{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:14px}.layout{display:grid;grid-template-columns:minmax(0,1.35fr) minmax(280px,.9fr);gap:14px}"
		   ".panel{background:#fff;border:1px solid #d9e5dc;border-radius:8px;margin-bottom:14px;box-shadow:0 5px 16px rgba(24,37,29,.045);overflow:hidden;animation:rise .22s ease-out}.panel.hot{animation:pulse .7s ease-out}.formtop{border-bottom:1px solid #e7eee8;padding:14px 16px;display:flex;align-items:center;justify-content:space-between;gap:10px}.title{font-size:16px;font-weight:800}.pad{padding:16px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:9px}.wide{grid-column:1/-1}"
		   ".kv{border-bottom:1px solid #edf2ee;padding:8px 0}.summary .kv{background:#fff;border:1px solid #d9e5dc;border-radius:8px;padding:11px 13px}.k{font-size:12px;color:#6d7b71}.v{font-size:14px;font-weight:800;word-break:break-all;margin-top:3px}.smallv{font-size:12px;font-weight:700;line-height:1.45}"
		   ".twocol{display:grid;grid-template-columns:1fr 1fr;gap:10px}label{display:block;font-size:13px;font-weight:800;margin:11px 0 5px}"
		   "input{width:100%%;height:40px;border:1px solid #b8c7bb;border-radius:6px;padding:9px 10px;font-size:14px;background:#fff;outline:none;transition:border-color .15s,box-shadow .15s}"
		   "input:focus{border-color:#2f7d4f;box-shadow:0 0 0 3px #dfeee5}.check{display:flex;gap:7px;align-items:center;margin:12px 0}.check input{width:auto;height:auto}.check label{margin:0;font-weight:700}"
		   ".actions{display:flex;gap:9px;flex-wrap:wrap;margin-top:14px}button{height:40px;border:1px solid #2f7d4f;border-radius:6px;background:#2f7d4f;color:#fff;font-size:14px;font-weight:800;padding:0 17px;cursor:pointer;transition:background .15s,transform .15s,opacity .15s}button:hover{transform:translateY(-1px);background:#256f43}button.busy{opacity:.72;pointer-events:none}button.alt,button.scan{background:#fff;color:#2f7d4f}"
		   ".tablewrap{overflow:auto}.saved{border:1px solid #edf2ee;border-radius:8px;padding:10px;margin-bottom:9px;display:flex;justify-content:space-between;gap:10px;align-items:center}.savedact{display:flex;gap:8px;flex-wrap:wrap}.savedact form{margin:0}.pick{height:32px;padding:0 12px}.ssidcell{font-weight:800;color:#1d3b29}.tag{display:inline-block;margin-left:5px;border-radius:5px;background:#e4f1e8;color:#286542;padding:2px 5px;font-size:11px}.focusrow{background:#f0f8f2}.defrow{background:#f8fbf3}.tinylink{font-size:12px;font-weight:800;color:#2f7d4f;border:1px solid #d1e5d7;border-radius:999px;padding:6px 9px;background:#fbfffc}"
		   "table{width:100%%;border-collapse:collapse;font-size:13px;min-width:680px}th,td{text-align:left;border-bottom:1px solid #e7eee8;padding:9px;vertical-align:top}th{color:#596960;background:#f8faf7;font-weight:800}"
		   "@media(max-width:860px){.shell{display:block}.side{position:static;height:auto;border-right:0;border-bottom:1px solid #dbe8dc;padding:12px}.brandbox{padding-bottom:6px}.nav{flex-direction:row;overflow:auto}.nav a{white-space:nowrap}.sidecard{display:none}main.page{padding:16px}.topline{align-items:flex-start}.layout,.grid,.twocol,.summary{grid-template-columns:1fr}.saved{align-items:flex-start;flex-direction:column}.topmeta{text-align:left}}"
		   "</style></head><body><div class=\"shell\"><aside class=\"side\">"
		   "<div class=\"brandbox\"><div class=\"brand\">WPA Mini</div><div class=\"sub\">WiFi STA 控制台</div></div>"
		   "<nav class=\"nav\"><a class=\"%s\" href=\"/\">控制台</a><a class=\"%s\" href=\"/interfaces\">网络接口</a><a class=\"%s\" href=\"/system_page\">系统信息</a></nav>"
		   "<div class=\"sidecard\"><div class=\"pill\">%s</div><div class=\"hint\">接口 %s</div><div class=\"hint\">SSID %s</div></div>"
		   "</aside><main class=\"page\"><div class=\"topline\"><div><div class=\"h1\">%s</div><div class=\"hint\">%s</div></div><div class=\"topmeta\"><div class=\"pill\">%s</div><div class=\"hint\">IP %s</div></div></div>",
		   esc_title, state_color, nav_active(page, WEB_PAGE_HOME),
		   nav_active(page, WEB_PAGE_INTERFACES),
		   nav_active(page, WEB_PAGE_SYSTEM),
		   state_label, esc_iface, esc_ssid[0] ? esc_ssid : "-",
		   esc_title, esc_subtitle, state_label,
		   esc_ip[0] ? esc_ip : "-");
	if (message && *message)
		buf_append(body, bodysz, "<section class=\"msg\">%s</section>",
			   esc_msg);
}

static void append_page_end(char *body, size_t bodysz)
{
	buf_append(body, bodysz,
		   "</main></div><script>"
		   "function pickNet(b){var s=document.getElementById('ssidInput'),p=document.getElementById('pskInput'),c=document.getElementById('connectPanel');if(s)s.value=b.getAttribute('data-ssid')||'';if(c){c.classList.remove('hot');void c.offsetWidth;c.classList.add('hot');c.scrollIntoView({behavior:'smooth',block:'start'});}if(p)p.focus();}"
		   "document.addEventListener('submit',function(e){var b=e.target.querySelector('button[type=submit]');if(b){b.classList.add('busy');b.textContent=b.textContent+'...';}});"
		   "</script></body></html>");
}

static void append_home_content(char *body, size_t bodysz,
				const struct app_config *cfg,
				const struct runtime_status *st,
				const char *scan_html,
				const char *saved_html,
				const char *autostart_html)
{
	char esc_ssid[256], esc_iface[128], esc_state[128], esc_bssid[128];
	char esc_ip[128], esc_gw[128], esc_dns[256], esc_dns_path[512];
	char esc_relay_lan[128], esc_relay_subnet[128], esc_relay_wan[128];
	char esc_relay_members[256];
	char esc_sta_subnet[128], esc_lan_subnet[128];
	const char *connect_hint;
	const char *share_state;
	const char *share_action;
	const char *share_button;
	const char *share_class;
	int share_ready;
	int connected;

	html_escape(esc_ssid, sizeof(esc_ssid), st->ssid);
	html_escape(esc_iface, sizeof(esc_iface), cfg->iface);
	html_escape(esc_state, sizeof(esc_state), st->wpa_state);
	html_escape(esc_bssid, sizeof(esc_bssid), st->bssid);
	html_escape(esc_ip, sizeof(esc_ip), st->ip);
	html_escape(esc_gw, sizeof(esc_gw), st->gateway);
	html_escape(esc_dns, sizeof(esc_dns), st->dns);
	html_escape(esc_dns_path, sizeof(esc_dns_path), cfg->dns_path);
	html_escape(esc_relay_lan, sizeof(esc_relay_lan),
		    st->relay_lan_iface[0] ? st->relay_lan_iface : "br0");
	html_escape(esc_relay_members, sizeof(esc_relay_members),
		    st->relay_lan_members[0] ? st->relay_lan_members : "-");
	html_escape(esc_relay_subnet, sizeof(esc_relay_subnet),
		    st->relay_lan_subnet[0] ? st->relay_lan_subnet : "-");
	html_escape(esc_relay_wan, sizeof(esc_relay_wan),
		    st->relay_wan_iface[0] ? st->relay_wan_iface : cfg->iface);
	html_escape(esc_sta_subnet, sizeof(esc_sta_subnet),
		    st->sta_subnet[0] ? st->sta_subnet : "-");
	html_escape(esc_lan_subnet, sizeof(esc_lan_subnet),
		    st->lan_subnet[0] ? st->lan_subnet : "-");
	connected = runtime_is_connected(st);
	share_ready = connected && st->default_route_ready;
	connect_hint = share_ready && !st->sta_lan_conflict ?
		       "本设备已通过这个 WiFi 获取地址并具备出口路由" :
		       st->sta_lan_conflict ?
		       "已关联 WiFi，但上游网段和热点/USB 网段冲突；开启共享时会自动调整热点/USB 网段" :
		       connected && !st->default_route_ready ?
		       "已关联 WiFi，但没有默认网关，暂不能作为外网出口" :
		       "本设备已通过这个 WiFi 获取地址";
	share_state = st->sta_lan_conflict ? "需调整网段" :
		      connected && !st->default_route_ready ? "缺少网关" :
		      st->relay_enabled ? "已开启" : "未开启";
	share_action = st->relay_enabled ? "/relay_off" :
		       "/relay_on";
	share_button = st->relay_enabled ? "关闭共享网络" :
		       st->sta_lan_conflict ?
		       "自动调整网段并共享网络" :
		       "共享网络给热点和 USB 设备";
	share_class = st->relay_enabled ? " class=\"alt\"" : "";

	buf_append(body, bodysz,
		   "<div class=\"summary\">"
		   "<div class=\"kv\"><div class=\"k\">接口</div><div class=\"v\">%s</div></div>"
		   "<div class=\"kv\"><div class=\"k\">WPA 状态</div><div class=\"v\">%s</div></div>"
		   "<div class=\"kv\"><div class=\"k\">SSID</div><div class=\"v\">%s</div></div>"
		   "<div class=\"kv\"><div class=\"k\">IP</div><div class=\"v\">%s</div></div>"
		   "</div>"
		   "<div class=\"layout\">",
		   esc_iface, esc_state, esc_ssid[0] ? esc_ssid : "-",
		   esc_ip[0] ? esc_ip : "-");

	if (connected) {
		buf_append(body, bodysz,
			   "<section class=\"panel\" id=\"connectPanel\"><div class=\"formtop\"><div><div class=\"title\">当前连接</div><div class=\"hint\">%s</div></div></div>"
			   "<div class=\"pad\"><div class=\"grid\">"
			   "<div class=\"kv\"><div class=\"k\">SSID</div><div class=\"v\">%s</div></div>"
			   "<div class=\"kv\"><div class=\"k\">IP</div><div class=\"v\">%s</div></div>"
			   "<div class=\"kv\"><div class=\"k\">网关</div><div class=\"v\">%s</div></div>"
			   "<div class=\"kv\"><div class=\"k\">共享网络</div><div class=\"v\">%s</div></div>"
			   "<div class=\"kv\"><div class=\"k\">上游网段</div><div class=\"v\">%s</div></div>"
			   "<div class=\"kv\"><div class=\"k\">热点/USB 网段</div><div class=\"v\">%s</div></div>"
			   "</div><div class=\"actions\">"
			   "<form method=\"post\" action=\"%s\"><button type=\"submit\"%s>%s</button></form>"
			   "<form method=\"post\" action=\"/scan\"><button class=\"scan\" type=\"submit\">扫描 WiFi</button></form>"
			   "<form method=\"post\" action=\"/disconnect\"><button class=\"alt\" type=\"submit\">断开</button></form>"
			   "</div></div></section>",
			   connect_hint,
			   esc_ssid[0] ? esc_ssid : "-",
			   esc_ip[0] ? esc_ip : "-",
			   esc_gw[0] ? esc_gw : "-",
			   share_state,
			   esc_sta_subnet, esc_lan_subnet,
			   share_action, share_class, share_button);
	} else {
		buf_append(body, bodysz,
			   "<section class=\"panel\" id=\"connectPanel\"><div class=\"formtop\"><div><div class=\"title\">连接网络</div><div class=\"hint\">WPA/WPA2-PSK，DNS 文件：%s</div></div></div>"
			   "<div class=\"pad\"><form method=\"post\" action=\"/connect\">"
			   "<label>SSID</label><input id=\"ssidInput\" name=\"ssid\" maxlength=\"32\" value=\"%s\" autocomplete=\"off\" required>"
			   "<label>密码或 64 位 HEX PSK</label><input id=\"pskInput\" name=\"psk\" type=\"password\" autocomplete=\"off\" required>"
			   "<div class=\"twocol\"><div><label>DNS 1</label><input name=\"dns1\" value=\"" DEFAULT_DNS1 "\" inputmode=\"decimal\"></div>"
			   "<div><label>DNS 2</label><input name=\"dns2\" value=\"" DEFAULT_DNS2 "\" inputmode=\"decimal\"></div></div>"
			   "<div class=\"check\"><input id=\"hidden\" name=\"hidden\" value=\"1\" type=\"checkbox\"><label for=\"hidden\">隐藏 SSID</label></div>"
			   "<div class=\"check\"><input id=\"relay\" name=\"relay\" value=\"1\" type=\"checkbox\"><label for=\"relay\">连接后共享网络给热点和 USB 设备</label></div>"
			   "<div class=\"actions\"><button type=\"submit\">连接</button></div></form>"
			   "<div class=\"actions\"><form method=\"post\" action=\"/scan\"><button class=\"scan\" type=\"submit\">扫描 WiFi</button></form>"
			   "<form method=\"post\" action=\"/disconnect\"><button class=\"alt\" type=\"submit\">断开</button></form></div></div></section>",
			   esc_dns_path, esc_ssid);
	}

	buf_append(body, bodysz,
		   "<section class=\"panel\"><div class=\"formtop\"><div><div class=\"title\">运行信息</div><div class=\"hint\">当前接口状态</div></div><a class=\"tinylink\" href=\"/interfaces\">查看接口</a></div><div class=\"pad\"><div class=\"grid\">"
		   "<div class=\"kv\"><div class=\"k\">BSSID</div><div class=\"v\">%s</div></div>"
		   "<div class=\"kv\"><div class=\"k\">网关</div><div class=\"v\">%s</div></div>"
		   "<div class=\"kv\"><div class=\"k\">DNS</div><div class=\"v\">%s</div></div>"
		   "<div class=\"kv\"><div class=\"k\">引擎 PID</div><div class=\"v\">%ld</div></div>"
		   "<div class=\"kv\"><div class=\"k\">DHCP PID</div><div class=\"v\">%ld</div></div>"
		   "<div class=\"kv\"><div class=\"k\">中继/NAT</div><div class=\"v\">%s</div></div>"
		   "<div class=\"kv\"><div class=\"k\">下层网络</div><div class=\"v\">%s %s</div></div>"
		   "<div class=\"kv\"><div class=\"k\">热点/USB 接口</div><div class=\"v\">%s</div></div>"
		   "<div class=\"kv\"><div class=\"k\">上游出口</div><div class=\"v\">%s</div></div>"
		   "<div class=\"kv\"><div class=\"k\">ip_forward / NAT / DHCP</div><div class=\"v\">%d / %s / %s</div></div>"
		   "</div></div></section></div>%s%s%s",
		   esc_bssid[0] ? esc_bssid : "-",
		   esc_gw[0] ? esc_gw : "-",
		   esc_dns[0] ? esc_dns : "-",
		   st->engine_running ? (long)st->engine_pid : 0L,
		   st->dhcp_running ? (long)st->dhcp_pid : 0L,
		   st->relay_enabled ? "已启用" : "未启用",
		   esc_relay_lan, esc_relay_subnet,
		   esc_relay_members,
		   esc_relay_wan,
		   st->relay_ip_forward,
		   st->relay_nat_rule ? "存在" : "无",
		   st->relay_dhcp_running ? "运行" : "停止",
		   autostart_html, saved_html, scan_html);
}

static void render_page(int fd, const struct app_config *cfg,
			const char *message, const char *scan_text)
{
	struct runtime_status st;
	char *scan_html;
	char *saved_html;
	char *autostart_html;
	char *body;

	log_msg(cfg, "render home page message=%s scan=%d",
		message ? message : "", scan_text && *scan_text ? 1 : 0);
	scan_html = calloc(1, SCAN_HTML_MAX);
	saved_html = calloc(1, SAVED_HTML_MAX);
	autostart_html = calloc(1, AUTOSTART_HTML_MAX);
	body = calloc(1, PAGE_BODY_MAX);
	if (!scan_html || !saved_html || !autostart_html || !body) {
		free(scan_html);
		free(saved_html);
		free(autostart_html);
		free(body);
		log_msg(cfg, "render home allocation failed");
		http_send(fd, cfg, 500, "Internal Server Error", "text/plain",
			  "out of memory\n");
		return;
	}

	get_runtime_status(cfg, &st);
	build_scan_html(scan_text, scan_html, SCAN_HTML_MAX);
	build_saved_html(saved_html, SAVED_HTML_MAX);
	build_autostart_html(autostart_html, AUTOSTART_HTML_MAX);
	append_page_start(body, PAGE_BODY_MAX, cfg, &st, WEB_PAGE_HOME,
			  "控制台", "连接 WiFi、扫描网络、管理已保存配置", message);
	append_home_content(body, PAGE_BODY_MAX, cfg, &st, scan_html,
			    saved_html, autostart_html);
	append_page_end(body, PAGE_BODY_MAX);

	http_send(fd, cfg, 200, "OK", "text/html; charset=utf-8", body);
	free(scan_html);
	free(saved_html);
	free(autostart_html);
	free(body);
}

static void render_interfaces_page(int fd, const struct app_config *cfg)
{
	struct runtime_status st;
	char *content;
	char *body;

	log_msg(cfg, "render interfaces page");
	content = calloc(1, SYSTEM_HTML_MAX);
	body = calloc(1, PAGE_BODY_MAX);
	if (!content || !body) {
		free(content);
		free(body);
		http_send(fd, cfg, 500, "Internal Server Error", "text/plain",
			  "out of memory\n");
		return;
	}
	get_runtime_status(cfg, &st);
	build_interfaces_html(cfg, content, SYSTEM_HTML_MAX);
	append_page_start(body, PAGE_BODY_MAX, cfg, &st, WEB_PAGE_INTERFACES,
			  "网络接口", "接口、路由和 ARP 表，只读展示", NULL);
	buf_append(body, PAGE_BODY_MAX, "%s", content);
	append_page_end(body, PAGE_BODY_MAX);
	http_send(fd, cfg, 200, "OK", "text/html; charset=utf-8", body);
	free(content);
	free(body);
}

static void render_system_page(int fd, const struct app_config *cfg)
{
	struct runtime_status st;
	char *content;
	char *body;

	log_msg(cfg, "render system html page");
	content = calloc(1, SYSTEM_HTML_MAX);
	body = calloc(1, PAGE_BODY_MAX);
	if (!content || !body) {
		free(content);
		free(body);
		http_send(fd, cfg, 500, "Internal Server Error", "text/plain",
			  "out of memory\n");
		return;
	}
	get_runtime_status(cfg, &st);
	build_system_page_html(cfg, content, SYSTEM_HTML_MAX);
	append_page_start(body, PAGE_BODY_MAX, cfg, &st, WEB_PAGE_SYSTEM,
			  "系统信息", "主机状态、监听端口和关键挂载点", NULL);
	buf_append(body, PAGE_BODY_MAX, "%s", content);
	append_page_end(body, PAGE_BODY_MAX);
	http_send(fd, cfg, 200, "OK", "text/html; charset=utf-8", body);
	free(content);
	free(body);
}

static void render_status(int fd, const struct app_config *cfg)
{
	struct runtime_status st;
	char esc_ssid[256], esc_state[128], esc_bssid[128], esc_ip[128];
	char esc_gw[128], esc_dns[256], esc_key[128], esc_iface[128];
	char esc_dns_path[512], esc_relay_lan[128], esc_relay_subnet[128];
	char esc_relay_wan[128], esc_sta_subnet[128], esc_lan_subnet[128];
	char esc_relay_members[256];
	char body[4096];

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
	json_escape(esc_relay_lan, sizeof(esc_relay_lan), st.relay_lan_iface);
	json_escape(esc_relay_members, sizeof(esc_relay_members),
		    st.relay_lan_members);
	json_escape(esc_relay_subnet, sizeof(esc_relay_subnet),
		    st.relay_lan_subnet);
	json_escape(esc_relay_wan, sizeof(esc_relay_wan), st.relay_wan_iface);
	json_escape(esc_sta_subnet, sizeof(esc_sta_subnet), st.sta_subnet);
	json_escape(esc_lan_subnet, sizeof(esc_lan_subnet), st.lan_subnet);

	snprintf(body, sizeof(body),
		 "{\"engine_running\":%s,\"engine_pid\":%ld,"
		 "\"dhcp_running\":%s,\"dhcp_pid\":%ld,"
		 "\"iface\":\"%s\",\"wpa_state\":\"%s\",\"ssid\":\"%s\","
		 "\"bssid\":\"%s\",\"key_mgmt\":\"%s\",\"ip\":\"%s\","
		 "\"gateway\":\"%s\",\"dns\":\"%s\",\"dns_path\":\"%s\","
		 "\"sta_subnet\":\"%s\",\"lan_subnet\":\"%s\","
		 "\"default_route_ready\":%s,\"sta_lan_conflict\":%s,"
		 "\"relay_enabled\":%s,\"relay_lan_iface\":\"%s\","
		 "\"relay_lan_members\":\"%s\",\"relay_lan_subnet\":\"%s\","
		 "\"relay_wan_iface\":\"%s\","
		 "\"relay_ip_forward\":%d,\"relay_nat_rule\":%s,"
		 "\"relay_dhcp_running\":%s,"
		 "\"port\":%d}\n",
		 st.engine_running ? "true" : "false",
		 st.engine_running ? (long)st.engine_pid : 0L,
		 st.dhcp_running ? "true" : "false",
		 st.dhcp_running ? (long)st.dhcp_pid : 0L,
		 esc_iface, esc_state, esc_ssid, esc_bssid, esc_key,
		 esc_ip, esc_gw, esc_dns, esc_dns_path,
		 esc_sta_subnet, esc_lan_subnet,
		 st.default_route_ready ? "true" : "false",
		 st.sta_lan_conflict ? "true" : "false",
		 st.relay_enabled ? "true" : "false",
		 esc_relay_lan, esc_relay_members, esc_relay_subnet,
		 esc_relay_wan,
		 st.relay_ip_forward,
		 st.relay_nat_rule ? "true" : "false",
		 st.relay_dhcp_running ? "true" : "false",
		 cfg->port);
	http_send(fd, cfg, 200, "OK", "application/json", body);
}

static void render_system(int fd, const struct app_config *cfg)
{
	char *body;

	log_msg(cfg, "render system");
	body = calloc(1, SYSTEM_TEXT_MAX);
	if (!body) {
		http_send(fd, cfg, 500, "Internal Server Error", "text/plain",
			  "out of memory\n");
		return;
	}
	build_system_text(cfg, body, SYSTEM_TEXT_MAX);
	http_send(fd, cfg, 200, "OK", "text/plain; charset=utf-8", body);
	free(body);
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

static void connect_wifi_request(int fd, const struct app_config *cfg,
				 const char *ssid, const char *psk,
				 const char *dns1,
				 const char *dns2, int hidden, int use_route,
				 int relay, int remember)
{
	char use_dns1[64];
	char use_dns2[64];

	snprintf(use_dns1, sizeof(use_dns1), "%s",
		 dns1 && dns1[0] ? dns1 : DEFAULT_DNS1);
	snprintf(use_dns2, sizeof(use_dns2), "%s",
		 dns2 && dns2[0] ? dns2 : DEFAULT_DNS2);
	if (relay)
		use_route = 1;
	log_msg(cfg, "connect request ssid=%s hidden=%d route=%d relay=%d dns1=%s dns2=%s",
		ssid, hidden, use_route, relay, use_dns1, use_dns2);

	if (!valid_ipv4_or_empty(use_dns1) || !valid_ipv4_or_empty(use_dns2)) {
		log_msg(cfg, "connect rejected: invalid dns");
		render_page(fd, cfg, "DNS 必须是有效的 IPv4 地址。", NULL);
		return;
	}

	if (write_config(cfg->conf, cfg->ctrl_dir, ssid, psk, hidden) < 0) {
		log_msg(cfg, "connect rejected: config write failed errno=%d", errno);
		render_page(fd, cfg, "配置写入失败，请检查 SSID 和密码长度。", NULL);
		return;
	}

	stop_dhcp(cfg);
	stop_relay(cfg);
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

	if (remember)
		remember_wifi(ssid, psk, use_dns1, use_dns2, hidden,
			      use_route, relay);

	if (start_dhcp(cfg, use_dns1, use_dns2, use_route) < 0) {
		render_page(fd, cfg, "WiFi 已连接，但 udhcpc 启动失败。", NULL);
		return;
	}

	if (wait_ipv4_ready(cfg, 8000) < 0) {
		log_msg(cfg, "connect warning: DHCP no IP yet");
		render_page(fd, cfg, "WiFi 已连接，但 DHCP 暂未分配 IP。", NULL);
		return;
	}

	if (relay && start_relay(cfg, use_dns1, use_dns2) < 0) {
		render_page(fd, cfg, "WiFi 已连接，但中继/NAT 启用失败。", NULL);
		return;
	}

	log_msg(cfg, "connect completed");
	http_redirect(fd, cfg, "/");
}

static void handle_connect(int fd, const struct app_config *cfg,
			   const char *body)
{
	char ssid[96];
	char psk[128];
	char dns1[64];
	char dns2[64];
	char value[16];
	int hidden;
	int use_route;
	int relay;

	form_value(body, "ssid", ssid, sizeof(ssid));
	form_value(body, "psk", psk, sizeof(psk));
	form_value(body, "dns1", dns1, sizeof(dns1));
	form_value(body, "dns2", dns2, sizeof(dns2));
	hidden = form_value(body, "hidden", value, sizeof(value)) && value[0];
	relay = form_value(body, "relay", value, sizeof(value)) && value[0];
	use_route = 1;
	connect_wifi_request(fd, cfg, ssid, psk, dns1, dns2, hidden,
			     use_route, relay, 1);
}

static void handle_connect_saved(int fd, const struct app_config *cfg,
				 const char *body)
{
	struct saved_wifi items[SAVED_WIFI_MAX];
	char value[16];
	char *end;
	long parsed;
	int idx;
	int count;

	form_value(body, "idx", value, sizeof(value));
	if (!value[0]) {
		render_page(fd, cfg, "保存的 WiFi 不存在。", NULL);
		return;
	}
	errno = 0;
	parsed = strtol(value, &end, 10);
	if (errno || *end || parsed < 0 || parsed > INT_MAX) {
		render_page(fd, cfg, "保存的 WiFi 不存在。", NULL);
		return;
	}
	idx = (int)parsed;
	count = load_saved_wifi(items, SAVED_WIFI_MAX);
	if (idx < 0 || idx >= count) {
		render_page(fd, cfg, "保存的 WiFi 不存在。", NULL);
		return;
	}
	connect_wifi_request(fd, cfg, items[idx].ssid, items[idx].psk,
			     items[idx].dns1, items[idx].dns2, items[idx].hidden,
			     1, items[idx].relay, 1);
}

static void handle_forget(int fd, const struct app_config *cfg,
			  const char *body)
{
	char ssid[96];

	form_value(body, "ssid", ssid, sizeof(ssid));
	if (ssid[0])
		forget_wifi(ssid);
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

static void handle_autostart_on(int fd, const struct app_config *cfg)
{
	if (write_autostart_script(cfg) < 0) {
		log_msg(cfg, "autostart script write failed errno=%d", errno);
		render_page(fd, cfg,
			    "自启动脚本写入失败，请确认 /mnt/userdata/wpa_mini.run 存在并可执行。",
			    NULL);
		return;
	}

	if (install_autostart_hook() < 0) {
		log_msg(cfg, "autostart hook install failed errno=%d", errno);
		render_page(fd, cfg,
			    "已写入持久启动脚本，但系统启动钩子写入失败；根分区可能不可写。",
			    NULL);
		return;
	}

	log_msg(cfg, "autostart enabled");
	render_page(fd, cfg, "开机自启动已启用。", NULL);
}

static void handle_autostart_off(int fd, const struct app_config *cfg)
{
	int hook_failed = 0;

	if (disable_autostart(&hook_failed) < 0) {
		log_msg(cfg, "autostart disable incomplete hook_failed=%d errno=%d",
			hook_failed, errno);
		render_page(fd, cfg,
			    hook_failed ?
			    "自启动脚本已处理，但系统启动钩子移除失败。" :
			    "关闭自启动失败。",
			    NULL);
		return;
	}

	log_msg(cfg, "autostart disabled");
	render_page(fd, cfg, "开机自启动已关闭。", NULL);
}

static void handle_relay_on(int fd, const struct app_config *cfg)
{
	struct runtime_status st;
	char dns1[64];
	char dns2[64];

	get_runtime_status(cfg, &st);
	if (!runtime_is_connected(&st)) {
		render_page(fd, cfg, "请先连接 WiFi，获取 IP 后才能共享网络。", NULL);
		return;
	}
	if (!st.default_route_ready) {
		render_page(fd, cfg,
			    "不能开启共享网络：当前 WiFi 没有默认网关，设备还不能通过它访问外网。",
			    NULL);
		return;
	}

	read_dns_pair(cfg->dns_path, dns1, sizeof(dns1), dns2, sizeof(dns2));
	if (!dns1[0])
		snprintf(dns1, sizeof(dns1), "%s", DEFAULT_DNS1);
	if (!dns2[0])
		snprintf(dns2, sizeof(dns2), "%s", DEFAULT_DNS2);

	if (start_relay(cfg, dns1, dns2) < 0) {
		render_page(fd, cfg, "共享网络启用失败，请检查 br0、iptables 和日志。", NULL);
		return;
	}

	log_msg(cfg, "relay enabled by webui");
	render_page(fd, cfg, "已开启共享网络。", NULL);
}

static void handle_relay_fix_lan(int fd, const struct app_config *cfg)
{
	struct runtime_status st;
	uint32_t net_host;
	char new_subnet[64];
	char dns1[64];
	char dns2[64];

	get_runtime_status(cfg, &st);
	if (!runtime_is_connected(&st)) {
		render_page(fd, cfg, "请先连接 WiFi，获取 IP 后才能调整共享网段。", NULL);
		return;
	}
	if (!st.sta_lan_conflict) {
		http_redirect(fd, cfg, "/");
		return;
	}
	if (choose_lan_subnet(&net_host) < 0) {
		render_page(fd, cfg, "没有找到可用的热点/USB 网段。", NULL);
		return;
	}
	if (adjust_lan_subnet(cfg, net_host, new_subnet, sizeof(new_subnet)) < 0) {
		render_page(fd, cfg, "热点/USB 网段调整失败，请查看日志。", NULL);
		return;
	}

	stop_dhcp(cfg);
	if (start_dhcp(cfg, DEFAULT_DNS1, DEFAULT_DNS2, 1) < 0 ||
	    wait_ipv4_ready(cfg, 8000) < 0) {
		render_page(fd, cfg,
			    "热点/USB 网段已调整，但 WiFi 出口 DHCP 还没有恢复。",
			    NULL);
		return;
	}
	read_dns_pair(cfg->dns_path, dns1, sizeof(dns1), dns2, sizeof(dns2));
	if (!dns1[0])
		snprintf(dns1, sizeof(dns1), "%s", DEFAULT_DNS1);
	if (!dns2[0])
		snprintf(dns2, sizeof(dns2), "%s", DEFAULT_DNS2);
	if (start_relay(cfg, dns1, dns2) < 0) {
		render_page(fd, cfg,
			    "热点/USB 网段已调整，但共享网络启用失败。",
			    NULL);
		return;
	}
	log_msg(cfg, "relay fix lan completed subnet=%s", new_subnet);
	render_page(fd, cfg, "已调整热点/USB 网段并开启共享网络。", NULL);
}

static void handle_relay_off(int fd, const struct app_config *cfg)
{
	stop_relay(cfg);
	log_msg(cfg, "relay disabled by webui");
	render_page(fd, cfg, "已关闭共享网络。", NULL);
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
	} else if (strcmp(method, "GET") == 0 &&
		   strcmp(path, "/interfaces") == 0) {
		render_interfaces_page(fd, cfg);
	} else if (strcmp(method, "GET") == 0 &&
		   strcmp(path, "/system_page") == 0) {
		render_system_page(fd, cfg);
	} else if (strcmp(method, "GET") == 0 && strcmp(path, "/status") == 0) {
		render_status(fd, cfg);
	} else if (strcmp(method, "GET") == 0 && strcmp(path, "/system") == 0) {
		render_system(fd, cfg);
	} else if (strcmp(method, "GET") == 0 && strcmp(path, "/scan") == 0) {
		handle_scan_text(fd, cfg);
	} else if (strcmp(method, "POST") == 0 &&
		   strcmp(path, "/scan") == 0) {
		handle_scan_page(fd, cfg);
	} else if (strcmp(method, "POST") == 0 &&
		   strcmp(path, "/connect") == 0) {
		handle_connect(fd, cfg, body);
	} else if (strcmp(method, "POST") == 0 &&
		   strcmp(path, "/connect_saved") == 0) {
		handle_connect_saved(fd, cfg, body);
	} else if (strcmp(method, "POST") == 0 &&
		   strcmp(path, "/forget") == 0) {
		handle_forget(fd, cfg, body);
	} else if (strcmp(method, "POST") == 0 &&
		   strcmp(path, "/autostart_on") == 0) {
		handle_autostart_on(fd, cfg);
	} else if (strcmp(method, "POST") == 0 &&
		   strcmp(path, "/autostart_off") == 0) {
		handle_autostart_off(fd, cfg);
	} else if (strcmp(method, "POST") == 0 &&
		   strcmp(path, "/relay_on") == 0) {
		handle_relay_on(fd, cfg);
	} else if (strcmp(method, "POST") == 0 &&
		   strcmp(path, "/relay_fix_lan") == 0) {
		handle_relay_fix_lan(fd, cfg);
	} else if (strcmp(method, "POST") == 0 &&
		   strcmp(path, "/relay_off") == 0) {
		handle_relay_off(fd, cfg);
	} else if (strcmp(method, "POST") == 0 &&
		   strcmp(path, "/disconnect") == 0) {
		stop_dhcp(cfg);
		stop_relay(cfg);
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
	set_cloexec(s);

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
		set_cloexec(c);
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
	int relay = 0;
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

	while ((opt = getopt(argc, argv, "wi:s:p:c:C:D:P:L:r:l:u:HMNFnh")) != -1) {
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
		case 'N':
			relay = 1;
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

	if (write_config(cfg.conf, cfg.ctrl_dir, ssid, psk, hidden) < 0)
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
	stop_relay(&cfg);
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
	else if (relay && start_relay(&cfg, DEFAULT_DNS1, DEFAULT_DNS2) < 0)
		fprintf(stderr, "warning: failed to enable WiFi relay/NAT\n");

	log_msg(&cfg, "one-shot completed foreground=%d relay=%d",
		foreground, relay);
	if (foreground) {
		for (;;)
			pause();
	}

	fflush(stdout);
	fflush(stderr);
	_exit(0);
}
