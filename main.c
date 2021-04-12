/* SPDX-License-Identifier: GPL-2.0 */

#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubus.h>
#include <libubox/blobmsg_json.h>
#include <libubox/ulog.h>
#include <libubox/avl.h>
#include <libubox/avl-cmp.h>
#include <libubox/usock.h>

#include <uci.h>
#include <uci_blob.h>

struct port {
	struct avl_node avl;
	char *network;
	char *port;
	uint32_t hapd;
	struct uloop_fd hapd_fd;
	uint32_t netifd;
};

static struct blob_buf b;
static struct avl_tree port_avl;
static struct ubus_auto_conn conn;
static uint32_t hapd_id;

static void
netifd_handle_iface(struct port *port, int add, int force)
{
	int ret;

	if (!port->netifd)
		return;

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "name", port->port);

	ret = ubus_invoke(&conn.ctx, port->netifd, add ? "add_device" : "remove_device",
			  b.head, NULL, NULL, 2000);
	if (force)
		return;

	if (ret)
		ULOG_ERR("failed to %s %s to %s (%d/%d)\n",
			 add ? "add" : "remove", port->port,
			 port->network, ret, port->netifd);
	else if (add)
		ULOG_INFO("%s added to %s\n", port->port, port->network);
}

static void
hostapd_handle_fd(struct uloop_fd *fd, unsigned int events)
{
	struct port *p = container_of(fd, struct port, hapd_fd);
	static char buf[256];
	int len;

	while ((len = recv(fd->fd, buf, sizeof(buf) - 1, 0) > 0)) {
		// fprintf(stderr, "RX %d %d/%s\n", fd->fd, len, &buf[3]);
		if (strlen(buf) < 4)
			continue;
		if (!strncmp(&buf[3], "AP-STA-CONNECTED", 16)) {
			ULOG_INFO("client connected on %s\n", p->port);
			netifd_handle_iface(p, 1, 0);
		} else if (!strncmp(&buf[3], "AP-STA-DISCONNECTED", 19)) {
			ULOG_INFO("client disconnected on %s\n", p->port);
			netifd_handle_iface(p, 0, 0);
		}
	}
}

static void hostapd_write_conf(struct port *port)
{
	char *filename;
	FILE *fp;

	if (asprintf(&filename, "/var/run/hostapd-%s.conf", port->port) < 0)
		return;

	fp = fopen(filename, "w+");
	if (!fp)
		goto out;

	fprintf(fp, "driver=wired\n");
	fprintf(fp, "ieee8021x=1\n");
	fprintf(fp, "eap_server=1\n");
	fprintf(fp, "eap_user_file=/hostapd-%s.eap_user\n", port->network);
	fprintf(fp, "eap_reauth_period=3600\n");
	fprintf(fp, "ctrl_interface=/var/run/hostapd\n");
	fprintf(fp, "interface=%s\n", port->port);

	fclose(fp);

out:
	free(filename);
}

static void hostapd_provide_conf(struct port *port, int add, int force)
{
	char *filename;
	int ret;

	if (!hapd_id)
		return;

	if (asprintf(&filename, "/var/run/hostapd-%s.conf", port->port) < 0)
		return;

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "iface", port->port);
	blobmsg_add_string(&b, "config", filename);

	ret = ubus_invoke(&conn.ctx, hapd_id, add ? "config_add" : "config_remove",
			  b.head, NULL, NULL, 2000);
	free(filename);
	if (force)
		return;

	if (ret)
		ULOG_ERR("failed to %s %s to hostapd (%d/%d)\n",
			 port->port, add ? "add" : "remove", ret, hapd_id);
	else if (add)
		ULOG_INFO("%s added to hostapd\n", port->port);
}

static void config_load_network(struct uci_section *s)
{
	enum {
		WIRED1X_ATTR_NETWORK,
		WIRED1X_ATTR_PORTS,
		__WIRED1X_ATTR_MAX,
	};

	static const struct blobmsg_policy network_attrs[__WIRED1X_ATTR_MAX] = {
		[WIRED1X_ATTR_NETWORK] = { .name = "network", .type = BLOBMSG_TYPE_STRING },
		[WIRED1X_ATTR_PORTS] = { .name = "ports", .type = BLOBMSG_TYPE_STRING },
	};

	const struct uci_blob_param_list network_attr_list = {
		.n_params = __WIRED1X_ATTR_MAX,
		.params = network_attrs,
	};

	struct blob_buf b = {};
	char *ports, *port, *_port, *network, *_network;
	struct blob_attr *tb[__WIRED1X_ATTR_MAX] = { 0 };
	struct port *p;

	blob_buf_init(&b, 0);
	uci_to_blob(&b, s, &network_attr_list);
	blobmsg_parse(network_attrs, __WIRED1X_ATTR_MAX, tb, blob_data(b.head), blob_len(b.head));

	if (!tb[WIRED1X_ATTR_NETWORK] || !tb[WIRED1X_ATTR_PORTS])
		return;

	network = blobmsg_get_string(tb[WIRED1X_ATTR_NETWORK]);
	ports = blobmsg_get_string(tb[WIRED1X_ATTR_PORTS]);

	port = strtok(ports, " ");
	while (port) {
		char *obj;
		uint32_t id = 0;

		if (asprintf(&obj, "network.interface.%s", network) < 0)
			goto next;
		ubus_lookup_id(&conn.ctx, obj, &id);
		if (!id)
			ULOG_ERR("failed to lookup %s\n", obj);
		free(obj);
		p = calloc_a(sizeof(*p),
			     &_network, strlen(network) + 1,
			     &_port, strlen(port) + 1);
		strcpy(_network, network);
		strcpy(_port, port);
		p->port = _port;
		p->network = _network;
		p->netifd = id;
		p->avl.key = _port;
		avl_insert(&port_avl, &p->avl);
		ULOG_INFO("adding %s\n", port);
		hostapd_write_conf(p);
		netifd_handle_iface(p, 0, 1);
		hostapd_provide_conf(p, 0, 1);
		hostapd_provide_conf(p, 1, 0);
next:
		port = strtok(NULL, " ");
	}
	blob_buf_free(&b);
}

static void config_load(void)
{
	struct uci_context *uci = uci_alloc_context();
	struct uci_package *package = NULL;

	avl_init(&port_avl, avl_strcmp, false, NULL);

	if (!uci_load(uci, "wired1x", &package)) {
		struct uci_element *e;

		uci_foreach_element(&package->sections, e) {
			struct uci_section *s = uci_to_section(e);

			if (!strcmp(s->type, "network"))
				config_load_network(s);
		}
	}

	uci_unload(uci, package);
	uci_free_context(uci);
}

static void cleanup(void)
{
	struct port *port;

	avl_for_each_element(&port_avl, port, avl) {
		ULOG_INFO("shutting down %s\n", port->port);
		hostapd_provide_conf(port, 0, 1);
		netifd_handle_iface(port, 0, 1);
	}
}

static void
netifd_event(const char *type, const char *path, uint32_t id)
{
	struct port *port;

	avl_for_each_element(&port_avl, port, avl) {
		if (strcmp(port->network, &path[18]))
			continue;

		if (!strcmp("ubus.object.add", type)) {
			ULOG_INFO("%s - found netifd\n", port->port);
			port->netifd = id;
		} else if (!strcmp("ubus.object.remove", type)) {
			ULOG_INFO("%s - lost netifd\n", port->port);
			port->netifd = 0;
		}
	}
}

static void
hostapd_event(const char *type, uint32_t id)
{
	if (!strcmp("ubus.object.add", type)) {
		ULOG_INFO("found hostapd\n");
		hapd_id = id;
		config_load();
	} else if (!strcmp("ubus.object.remove", type)) {
		ULOG_INFO("lost hostapd\n");
		hapd_id = 0;
	}
}

static void
hostapd_iface_event(const char *type, const char *path, uint32_t id)
{
	const char *port = &path[8];
	struct port *p = avl_find_element(&port_avl, port, p, avl);

	if (!p)
		return;

	if (!strcmp("ubus.object.add", type)) {
		struct sockaddr_un local = {
			.sun_family = AF_UNIX,
		};
		char *socket_tx = NULL;

		ULOG_INFO("found %s\n", path);

		if (asprintf(&socket_tx, "/var/run/hostapd/%s", p->port) < 0) {
			ULOG_ERR("failed to connect to hostapd socket\n");
			goto out;
		}
		if (sprintf(local.sun_path, "/tmp/wpa_ctrl_%d-%s", getpid(), p->port) < 0) {
			ULOG_ERR("failed to connect to hostapd socket\n");
			goto out;
		}

		p->hapd = id;
		p->hapd_fd.cb = hostapd_handle_fd;
		p->hapd_fd.fd = usock(USOCK_UNIX | USOCK_UDP | USOCK_NONBLOCK, socket_tx, NULL);
		if (p->hapd_fd.fd < 0) {
			ULOG_ERR("failed to connect to %s\n", socket_tx);
		} else {
			unlink(local.sun_path);
			if (bind(p->hapd_fd.fd, (struct sockaddr *) &local,
				 sizeof(local)) < 0) {
				ULOG_ERR("failed to bind %s\n", local.sun_path);
				close(p->hapd_fd.fd);
				p->hapd_fd.fd = 0;
				goto out;
			}
			ULOG_ERR("connected to %s\n", socket_tx);
			uloop_fd_add(&p->hapd_fd, ULOOP_READ);
			if (send(p->hapd_fd.fd, "ATTACH", 6, 0) < 0)
				ULOG_ERR("failed to attach to hostapd\n");
		}
out:
		if (socket_tx)
			free(socket_tx);
	} else if (!strcmp("ubus.object.remove", type)) {
		p->hapd = 0;
		if (p->hapd_fd.fd) {
			ULOG_INFO("lost %s - closing\n", path);
			close(p->hapd_fd.fd);
			uloop_fd_delete(&p->hapd_fd);
			p->hapd_fd.fd = 0;
			netifd_handle_iface(p, 0, 1);
		}
		hostapd_provide_conf(p, 0, 0);
	}
}

static void
ubus_event(struct ubus_context *ctx,  struct ubus_event_handler *ev,
	   const char *type, struct blob_attr *msg)
{
	enum {
		EVENT_ID,
		EVENT_PATH,
		__EVENT_MAX
	};

	static const struct blobmsg_policy status_policy[__EVENT_MAX] = {
		[EVENT_ID] = { .name = "id", .type = BLOBMSG_TYPE_INT32 },
		[EVENT_PATH] = { .name = "path", .type = BLOBMSG_TYPE_STRING },
	};

	struct blob_attr *tb[__EVENT_MAX];
	const char *path;
	uint32_t id;

	blobmsg_parse(status_policy, __EVENT_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[EVENT_ID] || !tb[EVENT_PATH])
		return;

	path = blobmsg_get_string(tb[EVENT_PATH]);
	id = blobmsg_get_u32(tb[EVENT_ID]);

	if (!strcmp(path, "hostapd")) {
		hostapd_event(type, id);
		return;
	}

	if (!strncmp(path, "hostapd.", 8)) {
		hostapd_iface_event(type, path, id);
		return;
	}

	if (!strncmp(path, "network.interface.", 18)) {
		netifd_event(type, path, id);
		return;
	}
}

static struct ubus_event_handler status_handler = { .cb = ubus_event };

static void
ubus_connect_handler(struct ubus_context *ctx)
{
	ubus_register_event_handler(ctx, &status_handler, "ubus.object.add");
	ubus_register_event_handler(ctx, &status_handler, "ubus.object.remove");

	ubus_lookup_id(ctx, "hostapd", &hapd_id);
	hostapd_event(hapd_id ? "ubus.object.add" : "ubus.object.remove", hapd_id);
}

static void
signal_shutdown(int signal)
{
	cleanup();
	uloop_end();
}

int main(int argc, char **argv)
{
	ulog_open(ULOG_STDIO | ULOG_SYSLOG, LOG_DAEMON, "wired-802.1x");

	uloop_init();

	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, signal_shutdown);
	signal(SIGTERM, signal_shutdown);
	signal(SIGKILL, signal_shutdown);

	conn.cb = ubus_connect_handler;
	ubus_auto_connect(&conn);
	uloop_run();
	uloop_done();
	ubus_auto_shutdown(&conn);

	return 0;
}
