/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-ssh-service - ssh integration with NetworkManager
 *
 * Copyright (C) 2005 - 2008 Tim Niemueller <tim@niemueller.de>
 * Copyright (C) 2005 - 2010 Dan Williams <dcbw@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * $Id: nm-ssh-service.c 4232 2008-10-29 09:13:40Z tambeti $
 *
 */


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib/gi18n.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>

#include <NetworkManager.h>
#include <NetworkManagerVPN.h>
#include <nm-setting-vpn.h>

#include "nm-ssh-service.h"
#include "nm-utils.h"
#include "common/utils.h"

#if !defined(DIST_VERSION)
# define DIST_VERSION VERSION
#endif

static gboolean debug = FALSE;
static GMainLoop *loop = NULL;

#define NM_SSH_HELPER_PATH		LIBEXECDIR"/nm-ssh-service-ssh-helper"

G_DEFINE_TYPE (NMSshPlugin, nm_ssh_plugin, NM_TYPE_VPN_PLUGIN)

#define NM_SSH_PLUGIN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SSH_PLUGIN, NMSshPluginPrivate))

typedef struct {
	char *username;
	char *password;
	char *priv_key_pass;
	char *proxy_username;
	char *proxy_password;
	char *remote_gw;
	char *local_addr;
	char *remote_addr;

	/* fds for handling input/output of the SSH process */
	GIOChannel *ssh_stdin_channel;
	GIOChannel *ssh_stdout_channel;
	GIOChannel *ssh_stderr_channel;
	guint socket_channel_stdout_eventid;
	guint socket_channel_stderr_eventid;

	/* hold local and remote tun numbers */
	gint remote_tun_number;
	gint local_tun_number;

	// TODO remove
	GIOChannel *socket_channel;
	guint socket_channel_eventid;
} NMSshPluginIOData;

typedef struct {
	GPid	pid;
	guint connect_timer;
	guint connect_count;
	NMSshPluginIOData *io_data;
} NMSshPluginPrivate;

typedef struct {
	const char *name;
	GType type;
	gint int_min;
	gint int_max;
	gboolean address;
} ValidProperty;

static ValidProperty valid_properties[] = {
	{ NM_SSH_KEY_AUTH,                 G_TYPE_STRING, 0, 0, FALSE },
	{ NM_SSH_KEY_CA,                   G_TYPE_STRING, 0, 0, FALSE },
	{ NM_SSH_KEY_CERT,                 G_TYPE_STRING, 0, 0, FALSE },
	{ NM_SSH_KEY_CIPHER,               G_TYPE_STRING, 0, 0, FALSE },
	{ NM_SSH_KEY_COMP_LZO,             G_TYPE_BOOLEAN, 0, 0, FALSE },
	{ NM_SSH_KEY_CONNECTION_TYPE,      G_TYPE_STRING, 0, 0, FALSE },
	{ NM_SSH_KEY_FRAGMENT_SIZE,        G_TYPE_INT, 0, G_MAXINT, FALSE },
	{ NM_SSH_KEY_KEY,                  G_TYPE_STRING, 0, 0, FALSE },
	{ NM_SSH_KEY_LOCAL_IP,             G_TYPE_STRING, 0, 0, TRUE },
	{ NM_SSH_KEY_MSSFIX,               G_TYPE_BOOLEAN, 0, 0, FALSE },
	{ NM_SSH_KEY_PROTO_TCP,            G_TYPE_BOOLEAN, 0, 0, FALSE },
	{ NM_SSH_KEY_PORT,                 G_TYPE_INT, 1, 65535, FALSE },
	{ NM_SSH_KEY_PROXY_TYPE,           G_TYPE_STRING, 0, 0, FALSE },
	{ NM_SSH_KEY_PROXY_SERVER,         G_TYPE_STRING, 0, 0, FALSE },
	{ NM_SSH_KEY_PROXY_PORT,           G_TYPE_INT, 1, 65535, FALSE },
	{ NM_SSH_KEY_PROXY_RETRY,          G_TYPE_BOOLEAN, 0, 0, FALSE },
	{ NM_SSH_KEY_HTTP_PROXY_USERNAME,  G_TYPE_STRING, 0, 0, FALSE },
	{ NM_SSH_KEY_REMOTE,               G_TYPE_STRING, 0, 0, FALSE },
	{ NM_SSH_KEY_REMOTE_IP,            G_TYPE_STRING, 0, 0, TRUE },
	{ NM_SSH_KEY_RENEG_SECONDS,        G_TYPE_INT, 0, G_MAXINT, FALSE },
	{ NM_SSH_KEY_STATIC_KEY,           G_TYPE_STRING, 0, 0, FALSE },
	{ NM_SSH_KEY_STATIC_KEY_DIRECTION, G_TYPE_INT, 0, 1, FALSE },
	{ NM_SSH_KEY_TA,                   G_TYPE_STRING, 0, 0, FALSE },
	{ NM_SSH_KEY_TA_DIR,               G_TYPE_INT, 0, 1, FALSE },
	{ NM_SSH_KEY_TAP_DEV,              G_TYPE_BOOLEAN, 0, 0, FALSE },
	{ NM_SSH_KEY_TLS_REMOTE,	       G_TYPE_STRING, 0, 0, FALSE },
	{ NM_SSH_KEY_TUNNEL_MTU,           G_TYPE_INT, 0, G_MAXINT, FALSE },
	{ NM_SSH_KEY_USERNAME,             G_TYPE_STRING, 0, 0, FALSE },
	{ NM_SSH_KEY_PASSWORD"-flags",     G_TYPE_STRING, 0, 0, FALSE },
	{ NM_SSH_KEY_CERTPASS"-flags",     G_TYPE_STRING, 0, 0, FALSE },
	{ NM_SSH_KEY_NOSECRET,             G_TYPE_STRING, 0, 0, FALSE },
	{ NM_SSH_KEY_HTTP_PROXY_PASSWORD"-flags", G_TYPE_STRING, 0, 0, FALSE },
	{ NULL,                                G_TYPE_NONE, FALSE }
};

static ValidProperty valid_secrets[] = {
	{ NM_SSH_KEY_PASSWORD,             G_TYPE_STRING, 0, 0, FALSE },
	{ NM_SSH_KEY_CERTPASS,             G_TYPE_STRING, 0, 0, FALSE },
	{ NM_SSH_KEY_NOSECRET,             G_TYPE_STRING, 0, 0, FALSE },
	{ NM_SSH_KEY_HTTP_PROXY_PASSWORD,  G_TYPE_STRING, 0, 0, FALSE },
	{ NULL,                                G_TYPE_NONE, FALSE }
};

static gboolean
validate_address (const char *address)
{
	const char *p = address;

	if (!address || !strlen (address))
		return FALSE;

	/* Ensure it's a valid DNS name or IP address */
	while (*p) {
		if (!isalnum (*p) && (*p != '-') && (*p != '.'))
			return FALSE;
		p++;
	}
	return TRUE;
}

typedef struct ValidateInfo {
	ValidProperty *table;
	GError **error;
	gboolean have_items;
} ValidateInfo;

static void
validate_one_property (const char *key, const char *value, gpointer user_data)
{
	ValidateInfo *info = (ValidateInfo *) user_data;
	int i;

	if (*(info->error))
		return;

	info->have_items = TRUE;

	/* 'name' is the setting name; always allowed but unused */
	if (!strcmp (key, NM_SETTING_NAME))
		return;

	for (i = 0; info->table[i].name; i++) {
		ValidProperty prop = info->table[i];
		long int tmp;

		if (strcmp (prop.name, key))
			continue;

		switch (prop.type) {
		case G_TYPE_STRING:
			if (!prop.address || validate_address (value))
				return; /* valid */

			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("invalid address '%s'"),
			             key);
			break;
		case G_TYPE_INT:
			errno = 0;
			tmp = strtol (value, NULL, 10);
			if (errno == 0 && tmp >= prop.int_min && tmp <= prop.int_max)
				return; /* valid */

			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("invalid integer property '%s' or out of range [%d -> %d]"),
			             key, prop.int_min, prop.int_max);
			break;
		case G_TYPE_BOOLEAN:
			if (!strcmp (value, "yes") || !strcmp (value, "no"))
				return; /* valid */

			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("invalid boolean property '%s' (not yes or no)"),
			             key);
			break;
		default:
			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("unhandled property '%s' type %s"),
			             key, g_type_name (prop.type));
			break;
		}
	}

	/* Did not find the property from valid_properties or the type did not match */
	if (!info->table[i].name) {
		g_set_error (info->error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             _("property '%s' invalid or not supported"),
		             key);
	}
}

static gboolean
nm_ssh_properties_validate (NMSettingVPN *s_vpn, GError **error)
{
	GError *validate_error = NULL;
	ValidateInfo info = { &valid_properties[0], &validate_error, FALSE };

	nm_setting_vpn_foreach_data_item (s_vpn, validate_one_property, &info);
	if (!info.have_items) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
		             _("No VPN configuration options."));
		return FALSE;
	}

	if (validate_error) {
		*error = validate_error;
		return FALSE;
	}
	return TRUE;
}

static gboolean
nm_ssh_secrets_validate (NMSettingVPN *s_vpn, GError **error)
{
	GError *validate_error = NULL;
	ValidateInfo info = { &valid_secrets[0], &validate_error, FALSE };

	nm_setting_vpn_foreach_secret (s_vpn, validate_one_property, &info);
	if (!info.have_items) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
		             _("No VPN secrets!"));
		return FALSE;
	}

	if (validate_error) {
		*error = validate_error;
		return FALSE;
	}
	return TRUE;
}

static char *
ovpn_quote_string (const char *unquoted)
{
	char *quoted = NULL, *q;
	char *u = (char *) unquoted;

	g_return_val_if_fail (unquoted != NULL, NULL);

	/* FIXME: use unpaged memory */
	quoted = q = g_malloc0 (strlen (unquoted) * 2);
	while (*u) {
		/* Escape certain characters */
		if (*u == ' ' || *u == '\\' || *u == '"')
			*q++ = '\\';
		*q++ = *u++;
	}

	return quoted;
}

/* sscanf is evil, and since we can't use glib regexp stuff since it's still
 * too new for some distros, do a simple match here.
 */
static char *
get_detail (const char *input, const char *prefix)
{
	char *ret = NULL;
	guint32 i = 0;
	const char *p, *start;

	g_return_val_if_fail (prefix != NULL, NULL);

	if (!g_str_has_prefix (input, prefix))
		return NULL;

	/* Grab characters until the next ' */
	p = start = input + strlen (prefix);
	while (*p) {
		if (*p == '\'') {
			ret = g_malloc0 (i + 1);
			strncpy (ret, start, i);
			break;
		}
		p++, i++;
	}

	return ret;
}

static void
write_user_pass (GIOChannel *channel,
                 const char *authtype,
                 const char *user,
                 const char *pass)
{
	char *quser, *qpass, *buf;

	/* Quote strings passed back to ssh */
	quser = ovpn_quote_string (user);
	qpass = ovpn_quote_string (pass);
	buf = g_strdup_printf ("username \"%s\" \"%s\"\n"
	                       "password \"%s\" \"%s\"\n",
	                       authtype, quser,
	                       authtype, qpass);
	memset (qpass, 0, strlen (qpass));
	g_free (qpass);
	g_free (quser);

	/* Will always write everything in blocking channels (on success) */
	g_io_channel_write_chars (channel, buf, strlen (buf), NULL, NULL);
	g_io_channel_flush (channel, NULL);

	memset (buf, 0, strlen (buf));
	g_free (buf);
}

static gboolean
handle_management_socket (NMVPNPlugin *plugin,
                          GIOChannel *source,
                          GIOCondition condition,
                          NMVPNPluginFailure *out_failure)
{
	NMSshPluginIOData *io_data = NM_SSH_PLUGIN_GET_PRIVATE (plugin)->io_data;
	gboolean again = TRUE;
	char *str = NULL, *auth = NULL, *buf;

	if (!(condition & G_IO_IN))
		return TRUE;

	if (g_io_channel_read_line (source, &str, NULL, NULL, NULL) != G_IO_STATUS_NORMAL)
		return TRUE;

	if (strlen (str) < 1)
		goto out;

	auth = get_detail (str, ">PASSWORD:Need '");
	if (auth) {
		if (strcmp (auth, "Auth") == 0) {
			if (io_data->username != NULL && io_data->password != NULL)
				write_user_pass (source, auth, io_data->username, io_data->password);
			else
				g_warning ("Auth requested but one of username or password is missing");
		} else if (!strcmp (auth, "Private Key")) {
			if (io_data->priv_key_pass) {
				char *qpass;

				/* Quote strings passed back to ssh */
				qpass = ovpn_quote_string (io_data->priv_key_pass);
				buf = g_strdup_printf ("password \"%s\" \"%s\"\n", auth, qpass);
				memset (qpass, 0, strlen (qpass));
				g_free (qpass);

				/* Will always write everything in blocking channels (on success) */
				g_io_channel_write_chars (source, buf, strlen (buf), NULL, NULL);
				g_io_channel_flush (source, NULL);
				g_free (buf);
			} else
				g_warning ("Certificate password requested but private key password == NULL");
		} else if (strcmp (auth, "HTTP Proxy") == 0) {
			if (io_data->proxy_username != NULL && io_data->proxy_password != NULL)
				write_user_pass (source, auth, io_data->proxy_username, io_data->proxy_password);
			else
				g_warning ("HTTP Proxy auth requested but either proxy username or password is missing");
		} else {
			g_warning ("No clue what to send for username/password request for '%s'", auth);
			if (out_failure)
				*out_failure = NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED;
			again = FALSE;
		}
		g_free (auth);
	}

	auth = get_detail (str, ">PASSWORD:Verification Failed: '");
	if (auth) {
		if (!strcmp (auth, "Auth"))
			g_warning ("Password verification failed");
		else if (!strcmp (auth, "Private Key"))
			g_warning ("Private key verification failed");
		else
			g_warning ("Unknown verification failed: %s", auth);

		g_free (auth);

		if (out_failure)
			*out_failure = NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED;
		again = FALSE;
	}

out:
	g_free (str);
	return again;
}

static gboolean
handle_management_socket2 (NMVPNPlugin *plugin,
                          GIOChannel *source,
                          GIOCondition condition,
                          NMVPNPluginFailure *out_failure)
{
	NMSshPluginIOData *io_data = NM_SSH_PLUGIN_GET_PRIVATE (plugin)->io_data;
	gboolean again = TRUE;
	char *str = NULL, *auth = NULL, *buf;

	if (!(condition & G_IO_IN))
		return TRUE;

	if (g_io_channel_read_line (source, &str, NULL, NULL, NULL) != G_IO_STATUS_NORMAL)
		return TRUE;

	if (strlen (str) < 1)
		goto out;

	auth = get_detail (str, ">PASSWORD:Need '");
	if (auth) {
		if (strcmp (auth, "Auth") == 0) {
			if (io_data->username != NULL && io_data->password != NULL)
				write_user_pass (source, auth, io_data->username, io_data->password);
			else
				g_warning ("Auth requested but one of username or password is missing");
		} else if (!strcmp (auth, "Private Key")) {
			if (io_data->priv_key_pass) {
				char *qpass;

				/* Quote strings passed back to ssh */
				qpass = ovpn_quote_string (io_data->priv_key_pass);
				buf = g_strdup_printf ("password \"%s\" \"%s\"\n", auth, qpass);
				memset (qpass, 0, strlen (qpass));
				g_free (qpass);

				/* Will always write everything in blocking channels (on success) */
				g_io_channel_write_chars (source, buf, strlen (buf), NULL, NULL);
				g_io_channel_flush (source, NULL);
				g_free (buf);
			} else
				g_warning ("Certificate password requested but private key password == NULL");
		} else if (strcmp (auth, "HTTP Proxy") == 0) {
			if (io_data->proxy_username != NULL && io_data->proxy_password != NULL)
				write_user_pass (source, auth, io_data->proxy_username, io_data->proxy_password);
			else
				g_warning ("HTTP Proxy auth requested but either proxy username or password is missing");
		} else {
			g_warning ("No clue what to send for username/password request for '%s'", auth);
			if (out_failure)
				*out_failure = NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED;
			again = FALSE;
		}
		g_free (auth);
	}

	auth = get_detail (str, ">PASSWORD:Verification Failed: '");
	if (auth) {
		if (!strcmp (auth, "Auth"))
			g_warning ("Password verification failed");
		else if (!strcmp (auth, "Private Key"))
			g_warning ("Private key verification failed");
		else
			g_warning ("Unknown verification failed: %s", auth);

		g_free (auth);

		if (out_failure)
			*out_failure = NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED;
		again = FALSE;
	}

out:
	g_free (str);
	return again;
}

static gboolean
nm_ssh_stdout_cb (GIOChannel *source, GIOCondition condition, gpointer user_data)
{
	NMVPNPlugin *plugin = NM_VPN_PLUGIN (user_data);
	NMVPNPluginFailure failure = NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED;
	NMSshPluginIOData *io_data = NM_SSH_PLUGIN_GET_PRIVATE (plugin)->io_data;
	char *str = NULL, *auth = NULL, *buf;

	if (!(condition & G_IO_IN))
		return TRUE;

	if (g_io_channel_read_line (source, &str, NULL, NULL, NULL) != G_IO_STATUS_NORMAL)
		return TRUE;

	if (strlen (str) < 1) {
		g_free(str);
		return TRUE;
	}

	/* Probe for remote tun number */
	// TODO rather ugly and hardcoded
	if (strncmp (str, "debug1: Requesting tun unit", 27) == 0) {
		sscanf(str, "debug1: Requesting tun unit %d", &io_data->remote_tun_number);
		g_message("Remote tun: %d", io_data->remote_tun_number);
		g_message(str);
	} else if (strncmp (str, "debug1: sys_tun_open:", 21) == 0) {
		sscanf(str, "debug1: sys_tun_open: tun%d", &io_data->local_tun_number);
		g_message("Local tun: %d", io_data->local_tun_number);
		g_message(str);
		// TODO Starting time here for getting local interface up...
	} else if (strncmp (str, "Tunnel device open failed.", 26) == 0) {
		/* Opening of tun device failed... :( */
		g_warning("Tunnel device open failed.");
		nm_vpn_plugin_set_state (plugin, NM_VPN_SERVICE_STATE_STOPPED);
		// TODO use a proper regexp
		// TODO it comes neither on STDOUT nor STDERR WTF?!
		// TODO interaction is done after SSH opens a TTY, not good for us...
	} else if (strncmp (str, "The authenticity of host", 24) == 0) {
		/* User will have to accept this new host with its fingerprint */
		g_warning("It is not a known host, continue connecting?");
		// TODO PROMPT FOR USER!!
		//nm_vpn_plugin_set_state (plugin, NM_VPN_SERVICE_STATE_STOPPED);
	}
	// TODO PROBE FOR PASSWORD PROMPT HERE

	g_message(str);

	g_free(str);
	return TRUE;
}

static gboolean
nm_ssh_socket_data_cb (GIOChannel *source, GIOCondition condition, gpointer user_data)
{
	NMVPNPlugin *plugin = NM_VPN_PLUGIN (user_data);
	NMVPNPluginFailure failure = NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED;

	if (!handle_management_socket (plugin, source, condition, &failure)) {
		nm_vpn_plugin_failure (plugin, failure);
		nm_vpn_plugin_set_state (plugin, NM_VPN_SERVICE_STATE_STOPPED);
		return FALSE;
	}

	return TRUE;
}

// TODO TODO
static gboolean
nm_ssh_connect_timer_cb2 (gpointer data)
{
	NMSshPlugin *plugin = NM_SSH_PLUGIN (data);
	NMSshPluginPrivate *priv = NM_SSH_PLUGIN_GET_PRIVATE (plugin);
	struct sockaddr_in     serv_addr;
	gboolean               connected = FALSE;
	gint                   socket_fd = -1;
	NMSshPluginIOData *io_data = priv->io_data;

	priv->connect_count++;

	/* open socket and start listener */
	socket_fd = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (socket_fd < 0)
		return FALSE;

	serv_addr.sin_family = AF_INET;
	if (inet_pton (AF_INET, "127.0.0.1", &(serv_addr.sin_addr)) <= 0)
		g_warning ("%s: could not convert 127.0.0.1", __func__);
	serv_addr.sin_port = htons (1194);
 
	connected = (connect (socket_fd, (struct sockaddr *) &serv_addr, sizeof (serv_addr)) == 0);
	if (!connected) {
		close (socket_fd);
		if (priv->connect_count <= 30)
			return TRUE;

		priv->connect_timer = 0;

		g_warning ("Could not open management socket");
		nm_vpn_plugin_failure (NM_VPN_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
		nm_vpn_plugin_set_state (NM_VPN_PLUGIN (plugin), NM_VPN_SERVICE_STATE_STOPPED);
	} else {
		GIOChannel *ssh_socket_channel;
		guint ssh_socket_channel_eventid;

		ssh_socket_channel = g_io_channel_unix_new (socket_fd);
		ssh_socket_channel_eventid = g_io_add_watch (ssh_socket_channel,
		                                                 G_IO_IN,
		                                                 nm_ssh_socket_data_cb,
		                                                 plugin);

		g_io_channel_set_encoding (ssh_socket_channel, NULL, NULL);
		io_data->socket_channel = ssh_socket_channel;
		io_data->socket_channel_eventid = ssh_socket_channel_eventid;
	}

	priv->connect_timer = 0;
	return FALSE;
}

static void
send_ip4_config (DBusGConnection *connection, GHashTable *config)
{
	DBusGProxy *proxy;
	GError *err = NULL;

	proxy = dbus_g_proxy_new_for_name (connection,
								NM_DBUS_SERVICE_SSH,
								NM_VPN_DBUS_PLUGIN_PATH,
								NM_VPN_DBUS_PLUGIN_INTERFACE);

	// TODO Do I really need a reply here?
	// Seems to work also without...
	//dbus_g_proxy_call (proxy, "SetIp4Config", &err,
	dbus_g_proxy_call_no_reply (proxy, "SetIp4Config",
				    dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
				    config,
				    G_TYPE_INVALID,
				    G_TYPE_INVALID);

	if (err) {
		g_warning ("Could not send failure information: %s", err->message);
		g_error_free (err);
	}

	g_object_unref (proxy);
}

static GValue *
str_to_gvalue (const char *str, gboolean try_convert)
{
	GValue *val;

	/* Empty */
	if (!str || strlen (str) < 1)
		return NULL;

	if (!g_utf8_validate (str, -1, NULL)) {
		if (try_convert && !(str = g_convert (str, -1, "ISO-8859-1", "UTF-8", NULL, NULL, NULL)))
			str = g_convert (str, -1, "C", "UTF-8", NULL, NULL, NULL);

		if (!str)
			/* Invalid */
			return NULL;
	}

	val = g_slice_new0 (GValue);
	g_value_init (val, G_TYPE_STRING);
	g_value_set_string (val, str);

	return val;
}

static GValue *
addr_to_gvalue (const char *str)
{
	struct in_addr	temp_addr;
	GValue *val;

	/* Empty */
	if (!str || strlen (str) < 1)
		return NULL;

	if (inet_pton (AF_INET, str, &temp_addr) <= 0)
		return NULL;

	val = g_slice_new0 (GValue);
	g_value_init (val, G_TYPE_UINT);
	g_value_set_uint (val, temp_addr.s_addr);

	return val;
}

static gboolean
send_network_config (NMVPNPlugin *plugin)
{
	NMSshPluginPrivate *priv = NM_SSH_PLUGIN_GET_PRIVATE (plugin);

	DBusGConnection *connection;
	GHashTable *config;
	char *tmp;
	GValue *val;
	int i;
	GError *err = NULL;
	GValue *dns_list = NULL;
	GValue *nbns_list = NULL;
	GValue *dns_domain = NULL;
	struct in_addr temp_addr;
	char **iter;

	connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, &err);
	if (!connection) {
		g_warning ("Could not get the system bus: %s", err->message);
		// TODO TODO
		//nm_vpn_plugin_failure (plugin, err);
		nm_vpn_plugin_set_state (plugin, NM_VPN_SERVICE_STATE_STOPPED);
		return FALSE;
	}

	config = g_hash_table_new (g_str_hash, g_str_equal);

	// TODO TODO TODO
	// TODO TODO TODO
	// TODO TODO TODO
	//val = addr_to_gvalue ("172.16.40.1");
	//g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_INT_GATEWAY, val);

	//val = addr_to_gvalue ("172.16.40.2");
	//g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS, val);

	//val = addr_to_gvalue ("173.204.238.133");
	//g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_EXT_GATEWAY, val);
	g_warning ("local_addr %s", priv->io_data->local_addr);
	g_warning ("remote_addr %s", priv->io_data->remote_addr);
	g_warning ("remote_gw %s", priv->io_data->remote_gw);
	g_warning ("local_tun_interface %d", priv->io_data->local_tun_number);

	// Retrieve local address
	if (priv->io_data->local_addr != NULL)
	{
		val = addr_to_gvalue (priv->io_data->local_addr);
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS, val);
	}
	else
	{
		g_warning ("local_addr unset.");
	}

	// Retrieve remote address
	if (priv->io_data->remote_addr != NULL)
	{
		val = addr_to_gvalue (priv->io_data->remote_addr);
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_INT_GATEWAY, val);
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_PTP, val);
	}
	else
	{
		g_warning ("remote_addr unset.");
	}

	// Retrieve remote gw address
	if (priv->io_data->remote_gw != NULL)
	{
		val = addr_to_gvalue (priv->io_data->remote_gw);
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_EXT_GATEWAY, val);
	}
	else
	{
		g_warning ("remote_gw unset.");
	}

	// Retrieve tun interface
	if (priv->io_data->local_tun_number != -1)
	{
		//val = str_to_gvalue (priv->io_data->local_tun_number, FALSE);
		// TODO HARDCODED!!
		val = str_to_gvalue ("tun100", FALSE);
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_TUNDEV, val);
	}
	else
	{
		g_warning ("local_tun_interface unset.");
	}

	/*g_value_init (val, G_TYPE_UINT);
	g_value_set_uint (val, 32);
	g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_PREFIX, val);*/

	//val = str_to_gvalue ("tun100", FALSE);
	//g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_TUNDEV, val);

	send_ip4_config (connection, config);
	return TRUE;
}

static gint
nm_ssh_get_free_tun_device (void)
{
	gint tun_device;

	for (tun_device = 0; tun_device <= 255; tun_device++)
	{
		if (system("/sbin/ifconfig tun" + itoa(tun_device)))
		{
			return tun_device;
		}
	}
	return -1;
}

static gboolean
nm_ssh_connect_timer_cb (gpointer data)
{
	NMSshPlugin *plugin = NM_SSH_PLUGIN (data);
	NMSshPluginPrivate *priv = NM_SSH_PLUGIN_GET_PRIVATE (plugin);
	struct sockaddr_in     serv_addr;
	gboolean               connected = FALSE;
	gint                   socket_fd = -1;
	NMSshPluginIOData *io_data = priv->io_data;

	priv->connect_count++;


	if (system("/sbin/ifconfig tun100 172.16.40.2 netmask 255.255.255.252 pointopoint 172.16.40.1") != 0 &&
		priv->connect_count <= 30)
	{
		return TRUE;
	}

	g_warning ("Interface tun100 configured.");

	priv->connect_timer = 0;
	send_network_config(plugin);
	// Return false so we don't get called again
	return FALSE;
}

static void
nm_ssh_schedule_connect_timer (NMSshPlugin *plugin)
{
	NMSshPluginPrivate *priv = NM_SSH_PLUGIN_GET_PRIVATE (plugin);

	if (priv->connect_timer == 0)
		priv->connect_timer = g_timeout_add (1000, nm_ssh_connect_timer_cb, plugin);
}

static void
ssh_watch_cb (GPid pid, gint status, gpointer user_data)
{
	NMVPNPlugin *plugin = NM_VPN_PLUGIN (user_data);
	NMSshPluginPrivate *priv = NM_SSH_PLUGIN_GET_PRIVATE (plugin);
	NMVPNPluginFailure failure = NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED;
	guint error = 0;
	gboolean good_exit = FALSE;

	if (WIFEXITED (status)) {
		error = WEXITSTATUS (status);
		if (error != 0)
			g_warning ("ssh exited with error code %d", error);
    }
	else if (WIFSTOPPED (status))
		g_warning ("ssh stopped unexpectedly with signal %d", WSTOPSIG (status));
	else if (WIFSIGNALED (status))
		g_warning ("ssh died with signal %d", WTERMSIG (status));
	else
		g_warning ("ssh died from an unknown cause");
  
	/* Reap child if needed. */
	waitpid (priv->pid, NULL, WNOHANG);
	priv->pid = 0;

	/* SSH doesn't supply useful exit codes :( */
	switch (error) {
	case 0:
		good_exit = TRUE;
		break;
	default:
		failure = NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED;
		break;
	}

	/* Try to get the last bits of data from ssh */
	if (priv->io_data && priv->io_data->socket_channel) {
		GIOChannel *channel = priv->io_data->socket_channel;
		GIOCondition condition;

		while ((condition = g_io_channel_get_buffer_condition (channel)) & G_IO_IN) {
			if (!handle_management_socket (plugin, channel, condition, &failure)) {
				good_exit = FALSE;
				break;
			}
		}
	}

	if (!good_exit)
		nm_vpn_plugin_failure (plugin, failure);

	nm_vpn_plugin_set_state (plugin, NM_VPN_SERVICE_STATE_STOPPED);
}

static gboolean
validate_auth (const char *auth)
{
	if (auth) {
		if (   !strcmp (auth, NM_SSH_AUTH_NONE)
		    || !strcmp (auth, NM_SSH_AUTH_RSA_MD4)
		    || !strcmp (auth, NM_SSH_AUTH_MD5)
		    || !strcmp (auth, NM_SSH_AUTH_SHA1)
		    || !strcmp (auth, NM_SSH_AUTH_SHA224)
		    || !strcmp (auth, NM_SSH_AUTH_SHA256)
		    || !strcmp (auth, NM_SSH_AUTH_SHA384)
		    || !strcmp (auth, NM_SSH_AUTH_SHA512)
		    || !strcmp (auth, NM_SSH_AUTH_RIPEMD160))
			return TRUE;
	}
	return FALSE;
}

static const char *
validate_connection_type (const char *ctype)
{
	if (ctype) {
		if (   !strcmp (ctype, NM_SSH_CONTYPE_TLS)
		    || !strcmp (ctype, NM_SSH_CONTYPE_STATIC_KEY)
		    || !strcmp (ctype, NM_SSH_CONTYPE_PASSWORD)
		    || !strcmp (ctype, NM_SSH_CONTYPE_PASSWORD_TLS))
			return ctype;
	}
	return NULL;
}

static const char *
nm_find_ssh (void)
{
	static const char *ssh_binary_paths[] = {
		"/usr/bin/ssh",
		"/bin/ssh",
		"/usr/local/bin/ssh",
		NULL
	};
	const char  **ssh_binary = ssh_binary_paths;

	while (*ssh_binary != NULL) {
		if (g_file_test (*ssh_binary, G_FILE_TEST_EXISTS))
			break;
		ssh_binary++;
	}

	return *ssh_binary;
}

static void
free_ssh_args (GPtrArray *args)
{
	g_ptr_array_foreach (args, (GFunc) g_free, NULL);
	g_ptr_array_free (args, TRUE);
}

static void
add_ssh_arg (GPtrArray *args, const char *arg)
{
	g_return_if_fail (args != NULL);
	g_return_if_fail (arg != NULL);

	g_ptr_array_add (args, (gpointer) g_strdup (arg));
}

static gboolean
add_ssh_arg_int (GPtrArray *args, const char *arg)
{
	long int tmp_int;

	g_return_val_if_fail (args != NULL, FALSE);
	g_return_val_if_fail (arg != NULL, FALSE);

	/* Convert -> int and back to string for security's sake since
	 * strtol() ignores some leading and trailing characters.
	 */
	errno = 0;
	tmp_int = strtol (arg, NULL, 10);
	if (errno != 0)
		return FALSE;
	g_ptr_array_add (args, (gpointer) g_strdup_printf ("%d", (guint32) tmp_int));
	return TRUE;
}

static void
add_cert_args (GPtrArray *args, NMSettingVPN *s_vpn)
{
	const char *ca, *cert, *key;

	g_return_if_fail (args != NULL);
	g_return_if_fail (s_vpn != NULL);

	ca = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_CA);
	cert = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_CERT);
	key = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_KEY);

	if (   ca && strlen (ca)
	    && cert && strlen (cert)
	    && key && strlen (key)
	    && !strcmp (ca, cert)
	    && !strcmp (ca, key)) {
		add_ssh_arg (args, "--pkcs12");
		add_ssh_arg (args, ca);
	} else {
		if (ca && strlen (ca)) {
			add_ssh_arg (args, "--ca");
			add_ssh_arg (args, ca);
		}

		if (cert && strlen (cert)) {
			add_ssh_arg (args, "--cert");
			add_ssh_arg (args, cert);
		}

		if (key && strlen (key)) {
			add_ssh_arg (args, "--key");
			add_ssh_arg (args, key);
		}
	}
}

static gboolean
nm_ssh_start_ssh_binary (NMSshPlugin *plugin,
                                 NMSettingVPN *s_vpn,
                                 const char *default_username,
                                 GError **error)
{
	NMSshPluginPrivate *priv = NM_SSH_PLUGIN_GET_PRIVATE (plugin);
	const char *ssh_binary, *auth, *connection_type, *tmp, *tmp2, *tmp3, *tmp4, *remote, *port;
	GPtrArray *args;
	GSource *ssh_watch;
	GPid pid;

	/* Find ssh */
	ssh_binary = nm_find_ssh ();
	if (!ssh_binary) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
		             _("Could not find the ssh binary."));
		return FALSE;
	}
  
 	auth = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_AUTH);
 	if (auth) {
 		if (!validate_auth(auth)) {
 			g_set_error (error,
 			             NM_VPN_PLUGIN_ERROR,
 			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
 			             "%s",
 			             _("Invalid HMAC auth."));
 			return FALSE;
 		}
 	}

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_CONNECTION_TYPE);
	connection_type = validate_connection_type (tmp);
	if (!connection_type) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
		             _("Invalid connection type."));
		return FALSE;
	}

	args = g_ptr_array_new ();
	add_ssh_arg (args, ssh_binary);

	remote = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_REMOTE);
	if (remote && strlen (remote)) {
		add_ssh_arg (args, "--remote");
		add_ssh_arg (args, remote);
	}

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_PROXY_TYPE);
	tmp2 = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_PROXY_SERVER);
	tmp3 = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_PROXY_PORT);
	tmp4 = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_PROXY_RETRY);
	if (tmp && strlen (tmp) && tmp2 && strlen (tmp2)) {
		if (!strcmp (tmp, "http")) {
			add_ssh_arg (args, "--http-proxy");
			add_ssh_arg (args, tmp2);
			add_ssh_arg (args, tmp3 ? tmp3 : "8080");
			add_ssh_arg (args, "auto");  /* Automatic proxy auth method detection */
			if (tmp4)
				add_ssh_arg (args, "--http-proxy-retry");
		} else if (!strcmp (tmp, "socks")) {
			add_ssh_arg (args, "--socks-proxy");
			add_ssh_arg (args, tmp2);
			add_ssh_arg (args, tmp3 ? tmp3 : "1080");
			if (tmp4)
				add_ssh_arg (args, "--socks-proxy-retry");
		} else {
			g_set_error (error,
				         NM_VPN_PLUGIN_ERROR,
				         NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
				         _("Invalid proxy type '%s'."),
				         tmp);
			return FALSE;
		}
	}

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_COMP_LZO);
	if (tmp && !strcmp (tmp, "yes"))
		add_ssh_arg (args, "--comp-lzo");

	add_ssh_arg (args, "--nobind");

	/* Device, either tun or tap */
	add_ssh_arg (args, "--dev");
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_TAP_DEV);
	if (tmp && !strcmp (tmp, "yes"))
		add_ssh_arg (args, "tap");
	else
		add_ssh_arg (args, "tun");

	/* Protocol, either tcp or udp */
	add_ssh_arg (args, "--proto");
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_PROTO_TCP);
	if (tmp && !strcmp (tmp, "yes"))
		add_ssh_arg (args, "tcp-client");
	else
		add_ssh_arg (args, "udp");

	/* Port */
	add_ssh_arg (args, "--port");
	port = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_PORT);
	if (port && strlen (port)) {
		if (!add_ssh_arg_int (args, port)) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Invalid port number '%s'."),
			             port);
			free_ssh_args (args);
			return FALSE;
		}
	} else {
		/* Default to IANA assigned port 1194 */
		add_ssh_arg (args, "1194");
	}

	/* Cipher */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_CIPHER);
	if (tmp && strlen (tmp)) {
		add_ssh_arg (args, "--cipher");
		add_ssh_arg (args, tmp);
	}

	/* Auth */
	if (auth) {
		add_ssh_arg (args, "--auth");
		add_ssh_arg (args, auth);
	}
	add_ssh_arg (args, "--auth-nocache");

	/* TA */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_TA);
	if (tmp && strlen (tmp)) {
		add_ssh_arg (args, "--tls-auth");
		add_ssh_arg (args, tmp);

		tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_TA_DIR);
		if (tmp && strlen (tmp))
			add_ssh_arg (args, tmp);
	}

	/* tls-remote */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_TLS_REMOTE);
	if (tmp && strlen (tmp)) {
                add_ssh_arg (args, "--tls-remote");
                add_ssh_arg (args, tmp);
	}

	/* Reneg seconds */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_RENEG_SECONDS);
	if (tmp && strlen (tmp)) {
		add_ssh_arg (args, "--reneg-sec");
		if (!add_ssh_arg_int (args, tmp)) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Invalid reneg seconds '%s'."),
			             tmp);
			free_ssh_args (args);
			return FALSE;
		}
	}

	if (debug) {
		add_ssh_arg (args, "--verb");
		add_ssh_arg (args, "10");
	} else {
		/* Syslog */
		add_ssh_arg (args, "--syslog");
		add_ssh_arg (args, "nm-ssh");
	}

	/* TUN MTU size */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_TUNNEL_MTU);
	if (tmp && strlen (tmp)) {
		add_ssh_arg (args, "--tun-mtu");
		if (!add_ssh_arg_int (args, tmp)) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Invalid TUN MTU size '%s'."),
			             tmp);
			free_ssh_args (args);
			return FALSE;
		}
	}

	/* fragment size */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_FRAGMENT_SIZE);
	if (tmp && strlen (tmp)) {
		add_ssh_arg (args, "--fragment");
		if (!add_ssh_arg_int (args, tmp)) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Invalid fragment size '%s'."),
			             tmp);
			free_ssh_args (args);
			return FALSE;
		}
	}

	/* mssfix */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_MSSFIX);
	if (tmp && !strcmp (tmp, "yes")) {
		add_ssh_arg (args, "--mssfix");
	}

	/* Punch script security in the face; this option was added to SSH 2.1-rc9
	 * and defaults to disallowing any scripts, a behavior change from previous
	 * versions.
	 */
	add_ssh_arg (args, "--script-security");
	add_ssh_arg (args, "2");

	/* Up script, called when connection has been established or has been restarted */
	add_ssh_arg (args, "--up");
	if (debug)
		add_ssh_arg (args, NM_SSH_HELPER_PATH " --helper-debug");
	else
		add_ssh_arg (args, NM_SSH_HELPER_PATH);
	add_ssh_arg (args, "--up-restart");

	/* Keep key and tun if restart is needed */
	add_ssh_arg (args, "--persist-key");
	add_ssh_arg (args, "--persist-tun");

	/* Management socket for localhost access to supply username and password */
	add_ssh_arg (args, "--management");
	add_ssh_arg (args, "127.0.0.1");
	/* with have nobind, thus 1194 should be free, it is the IANA assigned port */
	add_ssh_arg (args, "1194");
	/* Query on the management socket for user/pass */
	add_ssh_arg (args, "--management-query-passwords");

	/* do not let ssh setup routes or addresses, NM will handle it */
	add_ssh_arg (args, "--route-noexec");
	add_ssh_arg (args, "--ifconfig-noexec");

	/* Now append configuration options which are dependent on the configuration type */
	if (!strcmp (connection_type, NM_SSH_CONTYPE_TLS)) {
		add_ssh_arg (args, "--client");
		add_cert_args (args, s_vpn);
	} else if (!strcmp (connection_type, NM_SSH_CONTYPE_STATIC_KEY)) {
		tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_STATIC_KEY);
		if (tmp && strlen (tmp)) {
			add_ssh_arg (args, "--secret");
			add_ssh_arg (args, tmp);

			tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_STATIC_KEY_DIRECTION);
			if (tmp && strlen (tmp))
				add_ssh_arg (args, tmp);
		}

		add_ssh_arg (args, "--ifconfig");

		tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_LOCAL_IP);
		if (!tmp) {
			/* Insufficient data (FIXME: this should really be detected when validating the properties */
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             "%s",
			             _("Missing required local IP address for static key mode."));
			free_ssh_args (args);
			return FALSE;
		}
		add_ssh_arg (args, tmp);

		tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_REMOTE_IP);
		if (!tmp) {
			/* Insufficient data (FIXME: this should really be detected when validating the properties */
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             "%s",
			             _("Missing required remote IP address for static key mode."));
			free_ssh_args (args);
			return FALSE;
		}
		add_ssh_arg (args, tmp);
	} else if (!strcmp (connection_type, NM_SSH_CONTYPE_PASSWORD)) {
		/* Client mode */
		add_ssh_arg (args, "--client");
		/* Use user/path authentication */
		add_ssh_arg (args, "--auth-user-pass");

		tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_CA);
		if (tmp && strlen (tmp)) {
			add_ssh_arg (args, "--ca");
			add_ssh_arg (args, tmp);
		}
	} else if (!strcmp (connection_type, NM_SSH_CONTYPE_PASSWORD_TLS)) {
		add_ssh_arg (args, "--client");
		add_cert_args (args, s_vpn);
		/* Use user/path authentication */
		add_ssh_arg (args, "--auth-user-pass");
	} else {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             _("Unknown connection type '%s'."),
		             connection_type);
		free_ssh_args (args);
		return FALSE;
	}

	g_ptr_array_add (args, NULL);


	// TODO TODO
	priv->io_data = g_malloc0 (sizeof (NMSshPluginIOData));

	/* We'll need this when sending ip4 config data */
	// TODO TODO resolve remote
	priv->io_data->remote_gw = g_strdup("173.204.238.133");
	priv->io_data->local_addr = g_strdup("172.16.40.2");
	priv->io_data->remote_addr = g_strdup("172.16.40.1");
	priv->io_data->local_tun_number = 100;
	priv->io_data->remote_tun_number = 100;


	/* Get a local tun */
	priv->io_data->local_tun_number = nm_ssh_get_free_tun_device();
	if (priv->io_data->local_tun_number == -1)
	{
		g_warning("Could not assign a free tun device.");
		nm_vpn_plugin_set_state (plugin, NM_VPN_SERVICE_STATE_STOPPED);
	}

	// TODO TODO
	// TODO TODO
	// TODO TODO
	// TODO TODO
	// EVERYTHING IS HARDCODED!!!
	free_ssh_args (args);
	args = g_ptr_array_new ();
	add_ssh_arg (args, ssh_binary);

	add_ssh_arg (args, "-v");
	add_ssh_arg (args, "-p"); add_ssh_arg (args, port);
	add_ssh_arg (args, "-o"); add_ssh_arg (args, "ServerAliveInterval=10");
	add_ssh_arg (args, "-o"); add_ssh_arg (args, "TCPKeepAlive=yes");
	add_ssh_arg (args, "-w"); add_ssh_arg (args, ltoa(priv->io_data->local_tun_number) + ":100");
	add_ssh_arg (args, "-l"); add_ssh_arg (args, "root");
	add_ssh_arg (args, remote);
	//add_ssh_arg (args, "/sbin/ifconfig tun100 172.16.40.1 netmask 255.255.255.252");
	add_ssh_arg (args, "/sbin/ifconfig tun100 inet 172.16.40.1 netmask 255.255.255.252 pointopoint 172.16.40.2");
	g_ptr_array_add (args, NULL);

	/* Spawn with pipes */
	gint ssh_stdin_fd, ssh_stdout_fd, ssh_stderr_fd;
	if (!g_spawn_async_with_pipes (NULL, (char **) args->pdata, NULL,
						G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL, &pid,
						&ssh_stdin_fd, &ssh_stdout_fd, &ssh_stderr_fd,
						error)) {
		free_ssh_args (args);
		return FALSE;
	}
	free_ssh_args (args);

	g_message ("ssh started with pid %d", pid);

	/* Add a watch for the SSH stdout and stderr */
	priv->io_data->ssh_stdin_channel = g_io_channel_unix_new (ssh_stdin_fd);
	priv->io_data->ssh_stdout_channel = g_io_channel_unix_new (ssh_stdout_fd);
	priv->io_data->ssh_stderr_channel = g_io_channel_unix_new (ssh_stderr_fd);

	/* Set io watches on stdout and stderr */
	/* stdout */
	priv->io_data->socket_channel_stderr_eventid = g_io_add_watch (
		priv->io_data->ssh_stdout_channel,
   		G_IO_IN,
		nm_ssh_stdout_cb,
		plugin);
	/* stderr */
	priv->io_data->socket_channel_stderr_eventid = g_io_add_watch (
		priv->io_data->ssh_stderr_channel,
   		G_IO_IN,
		nm_ssh_stdout_cb,
		plugin);

	/* Set encoding to NULL */
	g_io_channel_set_encoding (priv->io_data->ssh_stdout_channel, NULL, NULL);
	g_io_channel_set_encoding (priv->io_data->ssh_stderr_channel, NULL, NULL);

	/* Add a watch for the process */
	priv->pid = pid;
	ssh_watch = g_child_watch_source_new (pid);
	g_source_set_callback (ssh_watch, (GSourceFunc) ssh_watch_cb, plugin, NULL);
	g_source_attach (ssh_watch, NULL);
	g_source_unref (ssh_watch);

	nm_ssh_schedule_connect_timer (plugin);
	return TRUE;

	/* Listen to the management socket for a few connection types:
	   PASSWORD: Will require username and password
	   X509USERPASS: Will require username and password and maybe certificate password
	   X509: May require certificate password
	*/
	if (   !strcmp (connection_type, NM_SSH_CONTYPE_TLS)
	    || !strcmp (connection_type, NM_SSH_CONTYPE_PASSWORD)
	    || !strcmp (connection_type, NM_SSH_CONTYPE_PASSWORD_TLS)
	    || nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_HTTP_PROXY_USERNAME)) {

		priv->io_data = g_malloc0 (sizeof (NMSshPluginIOData));

		tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_USERNAME);
		priv->io_data->username = tmp ? g_strdup (tmp) : NULL;
		/* Use the default username if it wasn't overridden by the user */
		if (!priv->io_data->username && default_username)
			priv->io_data->username = g_strdup (default_username);

		tmp = nm_setting_vpn_get_secret (s_vpn, NM_SSH_KEY_PASSWORD);
		priv->io_data->password = tmp ? g_strdup (tmp) : NULL;

		tmp = nm_setting_vpn_get_secret (s_vpn, NM_SSH_KEY_CERTPASS);
		priv->io_data->priv_key_pass = tmp ? g_strdup (tmp) : NULL;

		tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_HTTP_PROXY_USERNAME);
		priv->io_data->proxy_username = tmp ? g_strdup (tmp) : NULL;

		tmp = nm_setting_vpn_get_secret (s_vpn, NM_SSH_KEY_HTTP_PROXY_PASSWORD);
		priv->io_data->proxy_password = tmp ? g_strdup (tmp) : NULL;

		nm_ssh_schedule_connect_timer (plugin);
	}

	return TRUE;
}

static const char *
check_need_secrets (NMSettingVPN *s_vpn, gboolean *need_secrets)
{
	const char *tmp, *key, *ctype;

	g_return_val_if_fail (s_vpn != NULL, FALSE);
	g_return_val_if_fail (need_secrets != NULL, FALSE);

	*need_secrets = FALSE;

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_CONNECTION_TYPE);
	ctype = validate_connection_type (tmp);
	if (!ctype)
		return NULL;

	if (!strcmp (ctype, NM_SSH_CONTYPE_PASSWORD_TLS)) {
		/* Will require a password and maybe private key password */
		key = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_KEY);
		if (is_encrypted (key) && !nm_setting_vpn_get_secret (s_vpn, NM_SSH_KEY_CERTPASS))
			*need_secrets = TRUE;

		if (!nm_setting_vpn_get_secret (s_vpn, NM_SSH_KEY_PASSWORD))
			*need_secrets = TRUE;
	} else if (!strcmp (ctype, NM_SSH_CONTYPE_PASSWORD)) {
		/* Will require a password */
		if (!nm_setting_vpn_get_secret (s_vpn, NM_SSH_KEY_PASSWORD))
			*need_secrets = TRUE;
	} else if (!strcmp (ctype, NM_SSH_CONTYPE_TLS)) {
		/* May require private key password */
		key = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_KEY);
		if (is_encrypted (key) && !nm_setting_vpn_get_secret (s_vpn, NM_SSH_KEY_CERTPASS))
			*need_secrets = TRUE;
	} else {
		/* Static key doesn't need passwords */
	}

	/* HTTP Proxy might require a password; assume so if there's an HTTP proxy username */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_HTTP_PROXY_USERNAME);
	if (tmp && !nm_setting_vpn_get_secret (s_vpn, NM_SSH_KEY_HTTP_PROXY_PASSWORD))
		*need_secrets = TRUE;

	return ctype;
}

static gboolean
real_connect (NMVPNPlugin   *plugin,
              NMConnection  *connection,
              GError       **error)
{
	NMSettingVPN *s_vpn;
	const char *connection_type;
	const char *user_name;
	gboolean need_secrets;

	s_vpn = NM_SETTING_VPN (nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN));
	if (!s_vpn) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_CONNECTION_INVALID,
		             "%s",
		             _("Could not process the request because the VPN connection settings were invalid."));
		return FALSE;
	}

	/* Check if we need secrets and validate the connection type */
	connection_type = check_need_secrets (s_vpn, &need_secrets);
	if (!connection_type) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
		             _("Invalid connection type."));
		return FALSE;
	}

	user_name = nm_setting_vpn_get_user_name (s_vpn);

	/* Need a username for any password-based connection types */
	if (   !strcmp (connection_type, NM_SSH_CONTYPE_PASSWORD_TLS)
	    || !strcmp (connection_type, NM_SSH_CONTYPE_PASSWORD)) {
		if (!user_name && !nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_USERNAME)) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_CONNECTION_INVALID,
			             "%s",
			             _("Could not process the request because no username was provided."));
			return FALSE;
		}
	}

	/* Validate the properties */
	if (!nm_ssh_properties_validate (s_vpn, error))
		return FALSE;

	/* Validate secrets */
	if (need_secrets) {
		if (!nm_ssh_secrets_validate (s_vpn, error))
			return FALSE;
	}

	/* Finally try to start SSH */
	if (!nm_ssh_start_ssh_binary (NM_SSH_PLUGIN (plugin), s_vpn, user_name, error))
		return FALSE;

	return TRUE;
}

static gboolean
real_need_secrets (NMVPNPlugin *plugin,
                   NMConnection *connection,
                   char **setting_name,
                   GError **error)
{
	NMSettingVPN *s_vpn;
	const char *connection_type;
	gboolean need_secrets = FALSE;

	g_return_val_if_fail (NM_IS_VPN_PLUGIN (plugin), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	if (debug) {
		g_message ("%s: connection -------------------------------------", __func__);
		nm_connection_dump (connection);
	}

	s_vpn = NM_SETTING_VPN (nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN));
	if (!s_vpn) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_CONNECTION_INVALID,
		             "%s",
		             _("Could not process the request because the VPN connection settings were invalid."));
		return FALSE;
	}

	connection_type = check_need_secrets (s_vpn, &need_secrets);
	if (!connection_type) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
		             _("Invalid connection type."));
		return FALSE;
	}

	if (need_secrets)
		*setting_name = NM_SETTING_VPN_SETTING_NAME;

	return need_secrets;
}

static gboolean
ensure_killed (gpointer data)
{
	int pid = GPOINTER_TO_INT (data);

	if (kill (pid, 0) == 0)
		kill (pid, SIGKILL);

	return FALSE;
}

static gboolean
real_disconnect (NMVPNPlugin	 *plugin,
			  GError		**err)
{
	NMSshPluginPrivate *priv = NM_SSH_PLUGIN_GET_PRIVATE (plugin);

	if (priv->pid) {
		if (kill (priv->pid, SIGTERM) == 0)
			g_timeout_add (2000, ensure_killed, GINT_TO_POINTER (priv->pid));
		else
			kill (priv->pid, SIGKILL);

		g_message ("Terminated ssh daemon with PID %d.", priv->pid);
		priv->pid = 0;
	}

	return TRUE;
}

static void
nm_ssh_plugin_init (NMSshPlugin *plugin)
{
}

static void
nm_ssh_plugin_class_init (NMSshPluginClass *plugin_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (plugin_class);
	NMVPNPluginClass *parent_class = NM_VPN_PLUGIN_CLASS (plugin_class);

	g_type_class_add_private (object_class, sizeof (NMSshPluginPrivate));

	/* virtual methods */
	parent_class->connect      = real_connect;
	parent_class->need_secrets = real_need_secrets;
	parent_class->disconnect   = real_disconnect;
}

static void
plugin_state_changed (NMSshPlugin *plugin,
                      NMVPNServiceState state,
                      gpointer user_data)
{
	NMSshPluginPrivate *priv = NM_SSH_PLUGIN_GET_PRIVATE (plugin);

	switch (state) {
	case NM_VPN_SERVICE_STATE_UNKNOWN:
	case NM_VPN_SERVICE_STATE_INIT:
	case NM_VPN_SERVICE_STATE_SHUTDOWN:
	case NM_VPN_SERVICE_STATE_STOPPING:
	case NM_VPN_SERVICE_STATE_STOPPED:
	default:
		break;
	}
}

NMSshPlugin *
nm_ssh_plugin_new (void)
{
	NMSshPlugin *plugin;

	plugin =  (NMSshPlugin *) g_object_new (NM_TYPE_SSH_PLUGIN,
	                                            NM_VPN_PLUGIN_DBUS_SERVICE_NAME,
	                                            NM_DBUS_SERVICE_SSH,
	                                            NULL);
	if (plugin)
		g_signal_connect (G_OBJECT (plugin), "state-changed", G_CALLBACK (plugin_state_changed), NULL);

	return plugin;
}

static void
signal_handler (int signo)
{
	if (signo == SIGINT || signo == SIGTERM)
		g_main_loop_quit (loop);
}

static void
setup_signals (void)
{
	struct sigaction action;
	sigset_t mask;

	sigemptyset (&mask);
	action.sa_handler = signal_handler;
	action.sa_mask = mask;
	action.sa_flags = 0;
	sigaction (SIGTERM,  &action, NULL);
	sigaction (SIGINT,  &action, NULL);
}

static void
quit_mainloop (NMVPNPlugin *plugin, gpointer user_data)
{
	g_main_loop_quit ((GMainLoop *) user_data);
}

int
main (int argc, char *argv[])
{
	NMSshPlugin *plugin;
	gboolean persist = FALSE;
	GOptionContext *opt_ctx = NULL;

	GOptionEntry options[] = {
		{ "persist", 0, 0, G_OPTION_ARG_NONE, &persist, N_("Don't quit when VPN connection terminates"), NULL },
		{ "debug", 0, 0, G_OPTION_ARG_NONE, &debug, N_("Enable verbose debug logging (may expose passwords)"), NULL },
		{NULL}
	};

	g_type_init ();

	/* Parse options */
	opt_ctx = g_option_context_new ("");
	g_option_context_set_translation_domain (opt_ctx, "UTF-8");
	g_option_context_set_ignore_unknown_options (opt_ctx, FALSE);
	g_option_context_set_help_enabled (opt_ctx, TRUE);
	g_option_context_add_main_entries (opt_ctx, options, NULL);

	g_option_context_set_summary (opt_ctx,
		_("nm-vpnc-service provides integrated SSH capability to NetworkManager."));

	g_option_context_parse (opt_ctx, &argc, &argv, NULL);
	g_option_context_free (opt_ctx);

	if (getenv ("SSH_DEBUG"))
		debug = TRUE;

	if (debug)
		g_message ("nm-ssh-service (version " DIST_VERSION ") starting...");

	if (system ("/sbin/modprobe tun") == -1)
		exit (EXIT_FAILURE);

	plugin = nm_ssh_plugin_new ();
	if (!plugin)
		exit (EXIT_FAILURE);

	loop = g_main_loop_new (NULL, FALSE);

	if (!persist)
		g_signal_connect (plugin, "quit", G_CALLBACK (quit_mainloop), loop);

	setup_signals ();
	g_main_loop_run (loop);

	g_main_loop_unref (loop);
	g_object_unref (plugin);

	exit (EXIT_SUCCESS);
}
