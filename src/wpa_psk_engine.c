/*
 * Narrow WPA2-PSK station entrypoint for wpa_mini.
 *
 * The upstream supplicant supplies the nl80211, RSN, EAPOL and crypto state
 * machines. This file supplies only the process entrypoint and the small
 * datagram protocol required by the WebUI parent.
 */

#include "includes.h"

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include "common.h"
#include "common/ieee802_11_defs.h"
#include "config.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#include "scan.h"
#include "utils/eloop.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define PSK_CTRL_MAX 16384
#define PSK_CONFIG_LINE_MAX 512

struct psk_engine {
	struct wpa_global *global;
	struct wpa_supplicant *wpa_s;
	int ctrl_fd;
	char ctrl_path[PATH_MAX];
};

static int append_text(char *out, size_t outsz, size_t *used,
			       const char *fmt, ...)
{
	va_list ap;
	int n;

	if (*used >= outsz)
		return -1;
	va_start(ap, fmt);
	n = vsnprintf(out + *used, outsz - *used, fmt, ap);
	va_end(ap);
	if (n < 0 || (size_t)n >= outsz - *used)
		return -1;
	*used += (size_t)n;
	return 0;
}

static char *trim_text(char *text)
{
	char *end;

	while (*text == ' ' || *text == '\t' || *text == '\r' || *text == '\n')
		text++;
	end = text + strlen(text);
	while (end > text && (end[-1] == ' ' || end[-1] == '\t' ||
			      end[-1] == '\r' || end[-1] == '\n'))
		*--end = '\0';
	return text;
}

static int config_value_allowed(const char *name, const char *value)
{
	return (strcmp(name, "key_mgmt") == 0 && strcmp(value, "WPA-PSK") == 0) ||
	       (strcmp(name, "proto") == 0 && strcmp(value, "RSN") == 0) ||
	       (strcmp(name, "pairwise") == 0 && strcmp(value, "CCMP") == 0) ||
	       (strcmp(name, "group") == 0 && strcmp(value, "CCMP") == 0);
}

static int load_psk_network(struct wpa_config *config, const char *path,
				    struct wpa_ssid **out_ssid)
{
	FILE *fp;
	char line[PSK_CONFIG_LINE_MAX];
	struct wpa_ssid *ssid = NULL;
	int in_network = 0;
	int line_no = 0;
	int saw_key_mgmt = 0;
	int saw_proto = 0;
	int saw_pairwise = 0;
	int saw_group = 0;
	int ret = -1;

	if (!out_ssid)
		return -1;
	*out_ssid = NULL;

	fp = fopen(path, "r");
	if (!fp)
		return -1;

	while (fgets(line, sizeof(line), fp)) {
		char *pos;
		char *eq;
		line_no++;
		if (!strchr(line, '\n') && !feof(fp))
			goto out;
		pos = trim_text(line);
		if (!*pos || *pos == '#')
			continue;
		if (strcmp(pos, "network={") == 0) {
			if (in_network || ssid)
				goto out;
			ssid = wpa_config_add_network(config);
			if (!ssid)
				goto out;
			wpa_config_set_network_defaults(ssid);
			in_network = 1;
			continue;
		}
		if (strcmp(pos, "}") == 0) {
			if (!in_network)
				goto out;
			in_network = 0;
			continue;
		}
		if (!in_network)
			continue;

		eq = strchr(pos, '=');
		if (!eq)
			goto out;
		*eq++ = '\0';
		pos = trim_text(pos);
		eq = trim_text(eq);

		if (strcmp(pos, "ssid") == 0 || strcmp(pos, "psk") == 0) {
			if (wpa_config_set(ssid, pos, eq, 0) < 0)
				goto out;
		} else if (strcmp(pos, "scan_ssid") == 0) {
			if (strcmp(eq, "1") != 0)
				goto out;
			ssid->scan_ssid = 1;
		} else if (strcmp(pos, "key_mgmt") == 0 ||
			   strcmp(pos, "proto") == 0 ||
			   strcmp(pos, "pairwise") == 0 ||
			   strcmp(pos, "group") == 0) {
			if (!config_value_allowed(pos, eq))
				goto out;
			if (strcmp(pos, "key_mgmt") == 0)
				saw_key_mgmt = 1;
			else if (strcmp(pos, "proto") == 0)
				saw_proto = 1;
			else if (strcmp(pos, "pairwise") == 0)
				saw_pairwise = 1;
			else
				saw_group = 1;
		} else if (strcmp(pos, "ctrl_interface") != 0 &&
			   strcmp(pos, "ap_scan") != 0) {
			/* Reject options outside the fixed WPA2-PSK profile. */
			goto out;
		}
	}

	if (ferror(fp) || in_network)
		goto out;

	/* A valid scan-only profile intentionally has no network block. */
	if (!ssid) {
		ret = 1;
		goto out;
	}

	if (!ssid->ssid || !ssid->ssid_len ||
	    !ssid->psk_set || !saw_key_mgmt || !saw_proto || !saw_pairwise ||
	    !saw_group)
		goto out;

	ssid->key_mgmt = WPA_KEY_MGMT_PSK;
	ssid->proto = WPA_PROTO_RSN;
	ssid->pairwise_cipher = WPA_CIPHER_CCMP;
	ssid->group_cipher = WPA_CIPHER_CCMP;

	*out_ssid = ssid;
	ret = 0;
out:
	if (ret < 0 && ssid)
		wpa_config_remove_network(config, ssid->id);
	fclose(fp);
	if (ret < 0)
		wpa_printf(MSG_ERROR, "PSK config rejected at line %d", line_no);
	return ret;
}

static int build_status(struct psk_engine *engine, char *out, size_t outsz)
{
	struct wpa_supplicant *wpa_s = engine->wpa_s;
	struct wpa_ssid *ssid = wpa_s->current_ssid;
	const char *state = wpa_supplicant_state_txt(wpa_s->wpa_state);
	size_t used = 0;

	if (append_text(out, outsz, &used, "wpa_state=%s\n", state) < 0)
		return -1;
	if (ssid && ssid->ssid && ssid->ssid_len &&
	    append_text(out, outsz, &used, "ssid=%s\n",
			wpa_ssid_txt(ssid->ssid, ssid->ssid_len)) < 0)
		return -1;
	if (wpa_s->wpa_state >= WPA_ASSOCIATED &&
	    append_text(out, outsz, &used, "bssid=" MACSTR "\n",
			MAC2STR(wpa_s->bssid)) < 0)
		return -1;
	if (append_text(out, outsz, &used, "key_mgmt=WPA-PSK\n") < 0)
		return -1;
	if (append_text(out, outsz, &used, "proto=RSN\n") < 0)
		return -1;
	if (append_text(out, outsz, &used, "pairwise_cipher=CCMP\n") < 0)
		return -1;
	return (int)used;
}

static int build_scan_results(struct psk_engine *engine, char *out,
				      size_t outsz)
{
	struct wpa_scan_results *results;
	size_t used = 0;
	size_t i;

	if (append_text(out, outsz, &used,
			"bssid / frequency / signal level / flags / ssid\n") < 0)
		return -1;
	results = wpa_supplicant_get_scan_results(engine->wpa_s, NULL, 0);
	if (!results)
		return (int)used;
	for (i = 0; i < results->num; i++) {
		struct wpa_scan_res *res = results->res[i];
		const u8 *ie;
		const u8 *ssid_ie;
		const char *flags = "[ESS]";
		char ssid[256];

		if (!res)
			continue;
		ie = wpa_scan_get_ie(res, WLAN_EID_RSN);
		if (ie)
			flags = "[WPA2-PSK-CCMP][ESS]";
		ssid_ie = wpa_scan_get_ie(res, WLAN_EID_SSID);
		ssid[0] = '\0';
		if (ssid_ie && ssid_ie[1] <= 32)
			snprintf(ssid, sizeof(ssid), "%s",
				 wpa_ssid_txt(ssid_ie + 2, ssid_ie[1]));
		if (append_text(out, outsz, &used,
				MACSTR "\t%d\t%d\t%s\t%s\n",
				MAC2STR(res->bssid), res->freq, res->level,
				flags, ssid) < 0)
			break;
	}
	wpa_scan_results_free(results);
	return (int)used;
}

static void psk_ctrl_receive(int sock, void *eloop_ctx, void *sock_ctx)
{
	struct psk_engine *engine = eloop_ctx;
	struct sockaddr_un peer;
	char command[256];
	char reply[PSK_CTRL_MAX];
	socklen_t peer_len = sizeof(peer);
	ssize_t len;
	int reply_len;

	(void)sock_ctx;
	len = recvfrom(sock, command, sizeof(command) - 1, 0,
			      (struct sockaddr *)&peer, &peer_len);
	if (len < 0)
		return;
	command[len] = '\0';
	while (len > 0 && (command[len - 1] == '\n' ||
			   command[len - 1] == '\r'))
		command[--len] = '\0';

	if (strcmp(command, "PING") == 0) {
		snprintf(reply, sizeof(reply), "PONG\n");
		reply_len = 5;
	} else if (strcmp(command, "STATUS") == 0) {
		reply_len = build_status(engine, reply, sizeof(reply));
	} else if (strcmp(command, "SCAN") == 0) {
		/* Manual scans are allowed even when no network is configured. */
		engine->wpa_s->scan_req = MANUAL_SCAN_REQ;
		wpa_supplicant_req_scan(engine->wpa_s, 0, 0);
		snprintf(reply, sizeof(reply), "OK\n");
		reply_len = 3;
	} else if (strcmp(command, "SCAN_RESULTS") == 0) {
		reply_len = build_scan_results(engine, reply, sizeof(reply));
	} else if (strcmp(command, "TERMINATE") == 0) {
		wpa_supplicant_terminate_proc(engine->global);
		snprintf(reply, sizeof(reply), "OK\n");
		reply_len = 3;
	} else {
		snprintf(reply, sizeof(reply), "UNKNOWN COMMAND\n");
		reply_len = 16;
	}
	if (reply_len < 0)
		return;
	sendto(sock, reply, (size_t)reply_len, 0,
	       (struct sockaddr *)&peer, peer_len);
}

static int open_ctrl_socket(struct psk_engine *engine, const char *directory,
				    const char *ifname)
{
	struct sockaddr_un address;
	int n;

	if (mkdir(directory, 0700) < 0 && errno != EEXIST)
		return -1;
	n = snprintf(engine->ctrl_path, sizeof(engine->ctrl_path), "%s/%s",
		     directory, ifname);
	if (n < 0 || (size_t)n >= sizeof(engine->ctrl_path))
		return -1;
	engine->ctrl_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (engine->ctrl_fd < 0)
		return -1;
	unlink(engine->ctrl_path);
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	strncpy(address.sun_path, engine->ctrl_path,
		sizeof(address.sun_path) - 1);
	if (bind(engine->ctrl_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
		return -1;
	chmod(engine->ctrl_path, 0600);
	return eloop_register_read_sock(engine->ctrl_fd, psk_ctrl_receive,
				       engine, NULL);
}

static void close_ctrl_socket(struct psk_engine *engine)
{
	if (engine->ctrl_fd >= 0) {
		eloop_unregister_read_sock(engine->ctrl_fd);
		close(engine->ctrl_fd);
		engine->ctrl_fd = -1;
	}
	if (engine->ctrl_path[0])
		unlink(engine->ctrl_path);
}

static void usage(void)
{
	static const char text[] =
		"wpa_mini WPA2-PSK nl80211 engine\n"
		"usage: wpa_mini_engine -D nl80211 -i IFACE -c CONFIG -C CTRL_DIR\n";
	fputs(text, stderr);
}

int wpa_engine_main(int argc, char **argv)
{
	struct wpa_params params;
	struct wpa_interface iface;
	struct psk_engine engine;
	struct wpa_ssid *ssid;
	const char *driver = "nl80211";
	const char *ifname = NULL;
	const char *config_path = NULL;
	const char *ctrl_dir = NULL;
	int opt;
	int ret = -1;

	memset(&engine, 0, sizeof(engine));
	engine.ctrl_fd = -1;
	memset(&params, 0, sizeof(params));
	params.wpa_debug_level = MSG_INFO;
	while ((opt = getopt(argc, argv, "D:i:c:C:h")) != -1) {
		switch (opt) {
		case 'D': driver = optarg; break;
		case 'i': ifname = optarg; break;
		case 'c': config_path = optarg; break;
		case 'C': ctrl_dir = optarg; break;
		case 'h': usage(); return 0;
		default: usage(); return 2;
		}
	}
	if (!ifname || !config_path || !ctrl_dir)
		return 2;

	engine.global = wpa_supplicant_init(&params);
	if (!engine.global)
		return 1;
	memset(&iface, 0, sizeof(iface));
	iface.ifname = ifname;
	iface.driver = driver;
	engine.wpa_s = wpa_supplicant_add_iface(engine.global, &iface, NULL);
	if (!engine.wpa_s)
		goto out;
	if (load_psk_network(engine.wpa_s->conf, config_path, &ssid) < 0)
		goto out;
	if (open_ctrl_socket(&engine, ctrl_dir, ifname) < 0)
		goto out;
	if (ssid)
		wpa_supplicant_select_network(engine.wpa_s, ssid);
	ret = wpa_supplicant_run(engine.global);

out:
	close_ctrl_socket(&engine);
	wpa_supplicant_deinit(engine.global);
	return ret;
}
