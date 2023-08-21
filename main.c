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
	char *port;
	uint32_t hapd;
	struct uloop_fd hapd_fd;
};

struct account_info {
	char *addr;
	int port;
	char *secret;
};

struct radius_info {
	int enabled;
	char *nas_identifier;
	struct account_info auth;
	struct account_info acct;
	struct account_info coa;
};

static struct blob_buf b;
static struct avl_tree port_avl;
static struct ubus_auto_conn conn;
static uint32_t hapd_id;
static uint32_t netifd_id;
static char *ca;
static char *key;
static char *cert;
static char *identity;
static struct radius_info radius;

static void
netifd_handle_iface(struct port *port, int add)
{
	int ret;

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "name", port->port);
	blobmsg_add_u8(&b, "auth_status", add);

	ret = ubus_invoke(&conn.ctx, netifd_id, "set_state",
			  b.head, NULL, NULL, 2000);
	if (ret)
		ULOG_ERR("failed to %sauthenticate %s)\n",
			 add ? "" : "de-", port->port);
	else
		ULOG_INFO("%sauthenticated %s\n", add ? "" : "de-", port->port);
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
		if (!strncmp(&buf[3], "AP-STA-CONNECTED", 16) ||
		    !strncmp(&buf[3], "CTRL-EVENT-EAP-SUCCESS", 22)) {
			ULOG_INFO("client connected on %s\n", p->port);
			netifd_handle_iface(p, 1);
		} else if (!strncmp(&buf[3], "AP-STA-DISCONNECTED", 19)) {
			ULOG_INFO("client disconnected on %s\n", p->port);
			netifd_handle_iface(p, 0);
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
	fprintf(fp, "eap_reauth_period=3600\n");
	fprintf(fp, "ctrl_interface=/var/run/hostapd\n");
	fprintf(fp, "interface=%s\n", port->port);
	if (radius.enabled) {
		fprintf(fp, "dynamic_own_ip_addr=1\n");
		fprintf(fp, "dump_file=/tmp/hostapd.dump\n");
		if(radius.nas_identifier)
			fprintf(fp, "nas_identifier=%s\n", radius.nas_identifier);
		if(radius.auth.addr)
			fprintf(fp, "auth_server_addr=%s\n", radius.auth.addr);
		if(radius.auth.port)
			fprintf(fp, "auth_server_port=%d\n", radius.auth.port);
		if(radius.auth.secret)
			fprintf(fp, "auth_server_shared_secret=%s\n", radius.auth.secret);
		if(radius.acct.addr)
			fprintf(fp, "acct_server_addr=%s\n", radius.acct.addr);
		if(radius.acct.port)
			fprintf(fp, "acct_server_port=%d\n", radius.acct.port);
		if(radius.auth.secret)
			fprintf(fp, "acct_server_shared_secret=%s\n", radius.acct.secret);
		if(radius.coa.addr)
			fprintf(fp, "radius_das_port=%d\n", radius.coa.port);
		if(radius.coa.addr && radius.coa.secret )
			fprintf(fp, "radius_das_client=%s %s\n", radius.coa.addr, radius.coa.secret);
	} else {
		fprintf(fp, "eap_server=1\n");
		fprintf(fp, "eap_user_file=/var/run/hostapd-ieee8021x.eap_user\n");
	}
	if (ca)
		fprintf(fp, "ca_cert=%s\n", ca);
	if (cert)
		fprintf(fp, "server_cert=%s\n", cert);
	if (key)
		fprintf(fp, "private_key=%s\n", key);

	fclose(fp);

out:
	free(filename);
}

static void hostapd_provide_conf(struct port *port, int add, int force)
{
	char *filename;
	int ret;

	if (!hapd_id) {
		ULOG_ERR("hapd_id is not known\n");
		return;
	}

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
		IEEE8021X_ATTR_PORTS,
		__IEEE8021X_ATTR_MAX,
	};

	static const struct blobmsg_policy network_attrs[__IEEE8021X_ATTR_MAX] = {
		[IEEE8021X_ATTR_PORTS] = { .name = "ports", .type = BLOBMSG_TYPE_ARRAY },
	};

	const struct uci_blob_param_list network_attr_list = {
		.n_params = __IEEE8021X_ATTR_MAX,
		.params = network_attrs,
	};

	struct blob_buf b = {};
	char *port, *_port;
	struct blob_attr *tb[__IEEE8021X_ATTR_MAX] = { 0 };
	struct blob_attr *a;
	struct port *p;
        size_t rem;

	blob_buf_init(&b, 0);
	uci_to_blob(&b, s, &network_attr_list);
	blobmsg_parse(network_attrs, __IEEE8021X_ATTR_MAX, tb, blob_data(b.head), blob_len(b.head));

	if (!tb[IEEE8021X_ATTR_PORTS])
		return;

	blobmsg_for_each_attr(a, tb[IEEE8021X_ATTR_PORTS], rem) {
		port = blobmsg_get_string(a);
		p = calloc_a(sizeof(*p), &_port, strlen(port) + 1);
		strcpy(_port, port);
		p->port = _port;
		p->avl.key = _port;
		avl_insert(&port_avl, &p->avl);
		ULOG_INFO("adding %s\n", port);
		hostapd_write_conf(p);
		netifd_handle_iface(p, 0);
		hostapd_provide_conf(p, 0, 1);
		hostapd_provide_conf(p, 1, 0);
	}
	blob_buf_free(&b);
}

static void config_load_certificates(struct uci_section *s)
{
	enum {
		IEEE8021X_ATTR_CA,
		IEEE8021X_ATTR_CERT,
		IEEE8021X_ATTR_KEY,
		IEEE8021X_ATTR_ID,
		__IEEE8021X_ATTR_MAX,
	};

	static const struct blobmsg_policy network_attrs[__IEEE8021X_ATTR_MAX] = {
		[IEEE8021X_ATTR_CA] = { .name = "ca", .type = BLOBMSG_TYPE_STRING },
		[IEEE8021X_ATTR_CERT] = { .name = "cert", .type = BLOBMSG_TYPE_STRING },
		[IEEE8021X_ATTR_KEY] = { .name = "key", .type = BLOBMSG_TYPE_STRING },
		[IEEE8021X_ATTR_ID] = { .name = "identity", .type = BLOBMSG_TYPE_STRING },
	};

	const struct uci_blob_param_list network_attr_list = {
		.n_params = __IEEE8021X_ATTR_MAX,
		.params = network_attrs,
	};

	struct blob_attr *tb[__IEEE8021X_ATTR_MAX] = { 0 };

	blob_buf_init(&b, 0);
	uci_to_blob(&b, s, &network_attr_list);
	blobmsg_parse(network_attrs, __IEEE8021X_ATTR_MAX, tb, blob_data(b.head), blob_len(b.head));

	if (tb[IEEE8021X_ATTR_CA])
		ca = strdup(blobmsg_get_string(tb[IEEE8021X_ATTR_CA]));

	if (tb[IEEE8021X_ATTR_CERT])
		cert = strdup(blobmsg_get_string(tb[IEEE8021X_ATTR_CERT]));

	if (tb[IEEE8021X_ATTR_KEY])
		key = strdup(blobmsg_get_string(tb[IEEE8021X_ATTR_KEY]));

	if (tb[IEEE8021X_ATTR_ID])
		identity = strdup(blobmsg_get_string(tb[IEEE8021X_ATTR_ID]));
}

static void config_load_radius(struct uci_section *s)
{
	enum {
		IEEE8021X_ATTR_NAS_IDENTIFIER,
		IEEE8021X_ATTR_AUTH_SERVER_ADDR,
		IEEE8021X_ATTR_AUTH_SERVER_PORT,
		IEEE8021X_ATTR_AUTH_SERVER_SECRET,
		IEEE8021X_ATTR_ACCT_SERVER_ADDR,
		IEEE8021X_ATTR_ACCT_SERVER_PORT,
		IEEE8021X_ATTR_ACCT_SERVER_SECRET,
		IEEE8021X_ATTR_COA_SERVER_ADDR,
		IEEE8021X_ATTR_COA_SERVER_PORT,
		IEEE8021X_ATTR_COA_SERVER_SECRET,
		__IEEE8021X_ATTR_MAX,
	};

	static const struct blobmsg_policy radius_attrs[__IEEE8021X_ATTR_MAX] = {
		[IEEE8021X_ATTR_NAS_IDENTIFIER] = { .name = "nas_identifier", .type = BLOBMSG_TYPE_STRING },
		[IEEE8021X_ATTR_AUTH_SERVER_ADDR] = { .name = "auth_server_addr", .type = BLOBMSG_TYPE_STRING },
		[IEEE8021X_ATTR_AUTH_SERVER_PORT] = { .name = "auth_server_port", .type = BLOBMSG_TYPE_INT32 },
		[IEEE8021X_ATTR_AUTH_SERVER_SECRET] = { .name = "auth_server_secret", .type = BLOBMSG_TYPE_STRING },
		[IEEE8021X_ATTR_ACCT_SERVER_ADDR] = { .name = "acct_server_addr", .type = BLOBMSG_TYPE_STRING },
		[IEEE8021X_ATTR_ACCT_SERVER_PORT] = { .name = "acct_server_port", .type = BLOBMSG_TYPE_INT32 },
		[IEEE8021X_ATTR_ACCT_SERVER_SECRET] = { .name = "acct_server_secret", .type = BLOBMSG_TYPE_STRING },
		[IEEE8021X_ATTR_COA_SERVER_ADDR] = { .name = "coa_server_addr", .type = BLOBMSG_TYPE_STRING },
		[IEEE8021X_ATTR_COA_SERVER_PORT] = { .name = "coa_server_port", .type = BLOBMSG_TYPE_INT32 },
		[IEEE8021X_ATTR_COA_SERVER_SECRET] = { .name = "coa_server_secret", .type = BLOBMSG_TYPE_STRING },
	};

	const struct uci_blob_param_list radius_attr_list = {
		.n_params = __IEEE8021X_ATTR_MAX,
		.params = radius_attrs,
	};

	struct blob_attr *tb[__IEEE8021X_ATTR_MAX] = { 0 };

	blob_buf_init(&b, 0);
	uci_to_blob(&b, s, &radius_attr_list);
	blobmsg_parse(radius_attrs, __IEEE8021X_ATTR_MAX, tb, blob_data(b.head), blob_len(b.head));

	radius.enabled = 1;
	if (tb[IEEE8021X_ATTR_NAS_IDENTIFIER])
		radius.nas_identifier = strdup(blobmsg_get_string(tb[IEEE8021X_ATTR_NAS_IDENTIFIER]));

	if (tb[IEEE8021X_ATTR_AUTH_SERVER_ADDR])
		radius.auth.addr = strdup(blobmsg_get_string(tb[IEEE8021X_ATTR_AUTH_SERVER_ADDR]));

	if (tb[IEEE8021X_ATTR_AUTH_SERVER_PORT])
		radius.auth.port = blobmsg_get_u32(tb[IEEE8021X_ATTR_AUTH_SERVER_PORT]);

	if (tb[IEEE8021X_ATTR_AUTH_SERVER_SECRET])
		radius.auth.secret = strdup(blobmsg_get_string(tb[IEEE8021X_ATTR_AUTH_SERVER_SECRET]));

	if (tb[IEEE8021X_ATTR_ACCT_SERVER_ADDR])
		radius.acct.addr = strdup(blobmsg_get_string(tb[IEEE8021X_ATTR_ACCT_SERVER_ADDR]));

	if (tb[IEEE8021X_ATTR_ACCT_SERVER_PORT])
		radius.acct.port = blobmsg_get_u32(tb[IEEE8021X_ATTR_ACCT_SERVER_PORT]);

	if (tb[IEEE8021X_ATTR_ACCT_SERVER_SECRET])
		radius.acct.secret = strdup(blobmsg_get_string(tb[IEEE8021X_ATTR_ACCT_SERVER_SECRET]));

	if (tb[IEEE8021X_ATTR_COA_SERVER_ADDR])
		radius.coa.addr = strdup(blobmsg_get_string(tb[IEEE8021X_ATTR_COA_SERVER_ADDR]));

	if (tb[IEEE8021X_ATTR_COA_SERVER_PORT])
		radius.coa.port = blobmsg_get_u32(tb[IEEE8021X_ATTR_COA_SERVER_PORT]);

	if (tb[IEEE8021X_ATTR_COA_SERVER_SECRET])
		radius.coa.secret = strdup(blobmsg_get_string(tb[IEEE8021X_ATTR_COA_SERVER_SECRET]));
}

static void config_load(void)
{
	struct uci_context *uci = uci_alloc_context();
	struct uci_package *package = NULL;

	avl_init(&port_avl, avl_strcmp, false, NULL);

	if (!uci_load(uci, "ieee8021x", &package)) {
		struct uci_element *e;

		uci_foreach_element(&package->sections, e) {
			struct uci_section *s = uci_to_section(e);

			if (!strcmp(s->type, "network"))
				config_load_network(s);

			if (!strcmp(s->type, "certificates"))
				config_load_certificates(s);

			if (!strcmp(s->type, "radius"))
				config_load_radius(s);
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
		netifd_handle_iface(port, 0);
	}
}

static void
netifd_event(const char *type, const char *path, uint32_t id)
{
	if (!strcmp("ubus.object.add", type)) {
		ULOG_INFO("found netifd\n");
		netifd_id = id;
	} else if (!strcmp("ubus.object.remove", type)) {
		ULOG_INFO(" lost netifd\n");
		netifd_id = 0;
	}
}

static void
hostapd_event(const char *type, uint32_t id)
{
	if (!strcmp("ubus.object.add", type)) {
		ULOG_INFO("found hostapd\n");
		hapd_id = id;
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
			netifd_handle_iface(p, 0);
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

	if (!strncmp(path, "network.device", 18)) {
		netifd_event(type, path, id);
		return;
	}
}

static struct ubus_event_handler status_handler = { .cb = ubus_event };

static void
ubus_connect_handler(struct ubus_context *ctx)
{
	ULOG_INFO("connected to ubus");
	ubus_register_event_handler(ctx, &status_handler, "ubus.object.add");
	ubus_register_event_handler(ctx, &status_handler, "ubus.object.remove");

	ubus_lookup_id(ctx, "hostapd", &hapd_id);
	ULOG_INFO("hostapd id %d", hapd_id);

	ubus_lookup_id(ctx, "network.device", &netifd_id);
	ULOG_INFO("netifd id %d", netifd_id);

	config_load();
}

static void
signal_shutdown(int signal)
{
	cleanup();
	uloop_end();
}

int main(int argc, char **argv)
{
	ulog_open(ULOG_STDIO | ULOG_SYSLOG, LOG_DAEMON, "ieee8021x");

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
