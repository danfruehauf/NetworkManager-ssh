/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-ssh-service - ssh integration with NetworkManager
 *
 * Copyright (C) 2013 Dan Fruehauf <malkodan@gmail.com>
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
#include <gio/gio.h>
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
#include <netdb.h>
#include <ctype.h>
#include <errno.h>

#include <NetworkManager.h>
#include <NetworkManagerVPN.h>
#include <nm-setting-vpn.h>

#include "nm-ssh-service.h"
#include "nm-utils.h"

#if !defined(DIST_VERSION)
# define DIST_VERSION VERSION
#endif

static gboolean debug = FALSE;
static GMainLoop *loop = NULL;

// TODO hardcoded
#define SSH_AGENT_PARENT_DIR		"/tmp"
#define SSH_AGENT_SOCKET_ENV_VAR	"SSH_AUTH_SOCK"

G_DEFINE_TYPE (NMSshPlugin, nm_ssh_plugin, NM_TYPE_VPN_PLUGIN)

#define NM_SSH_PLUGIN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SSH_PLUGIN, NMSshPluginPrivate))

typedef struct {
	char *username;
	char *password;

	char *remote_gw;
	char *local_addr;
	char *remote_addr;
	char *netmask;

	/* fds for handling input/output of the SSH process */
	GIOChannel *ssh_stdin_channel;
	GIOChannel *ssh_stdout_channel;
	GIOChannel *ssh_stderr_channel;
	guint socket_channel_stdout_eventid;
	guint socket_channel_stderr_eventid;

	/* hold local and remote tun numbers */
	gint remote_tun_number;
	gint local_tun_number;
	guint mtu;
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
	/* TRUE/FALSE will dictate whether it is an address (X.X.X.X) or not */
	{ NM_SSH_KEY_REMOTE,               G_TYPE_STRING, 0, 0, FALSE },
	{ NM_SSH_KEY_LOCAL_IP,             G_TYPE_STRING, 0, 0, TRUE },
	{ NM_SSH_KEY_REMOTE_IP,            G_TYPE_STRING, 0, 0, TRUE },
	{ NM_SSH_KEY_NETMASK,              G_TYPE_STRING, 0, 0, TRUE },
	{ NM_SSH_KEY_PORT,                 G_TYPE_INT, 1, 65535, FALSE },
	{ NM_SSH_KEY_TUNNEL_MTU,           G_TYPE_INT, 1, 9000, FALSE },
	{ NM_SSH_KEY_EXTRA_OPTS,           G_TYPE_STRING, 0, 0, FALSE },
	{ NM_SSH_KEY_REMOTE_TUN,           G_TYPE_INT, 0, 255, FALSE },
	{ NULL,                            G_TYPE_NONE, FALSE }
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

static char *
resolve_hostname (const char *hostname)
{
	struct in_addr addr;
	char *ip;
	const char *p;
	gboolean is_name = FALSE;

	/* Check if it seems to be a hostname hostname */
	p = hostname;
	while (*p) {
		if (*p != '.' && !isdigit (*p)) {
			is_name = TRUE;
			break;
		}
		p++;
	}

	/* Resolve a hostname if required */
	if (is_name) {
		struct addrinfo hints;
		struct addrinfo *result = NULL, *rp;
		int err;

		memset (&hints, 0, sizeof (hints));

		hints.ai_family = AF_INET;
		hints.ai_flags = AI_ADDRCONFIG;
		err = getaddrinfo (hostname, NULL, &hints, &result);
		if (err != 0) {
			g_warning ("%s: failed to look up VPN gateway address '%s' (%d)",
			           __func__, hostname, err);
			return NULL;
		}

		/* FIXME: so what if the name resolves to multiple IP addresses?  We
		 * don't know which one pptp decided to use so we could end up using a
		 * different one here, and the VPN just won't work.
		 */
		for (rp = result; rp; rp = rp->ai_next) {
			if (   (rp->ai_family == AF_INET)
			    && (rp->ai_addrlen == sizeof (struct sockaddr_in))) {
				struct sockaddr_in *inptr = (struct sockaddr_in *) rp->ai_addr;

				//memcpy (&ip, &(inptr->sin_addr), sizeof (struct in_addr));
				ip = g_strdup(inet_ntoa (inptr->sin_addr));
				if (debug)
					g_message("Resolved gateway '%s'->'%s'", hostname, ip);
				break;
			}
		}

		freeaddrinfo (result);
	} else {
		errno = 0;
		if (inet_pton (AF_INET, hostname, &addr) <= 0) {
			g_warning ("%s: failed to convert VPN gateway address '%s' (%d)",
			           __func__, hostname, errno);
			return NULL;
		}
	}

	return ip;
}

static gboolean
send_network_config (NMSshPlugin *plugin)
{
	NMSshPluginPrivate *priv = NM_SSH_PLUGIN_GET_PRIVATE (plugin);

	DBusGConnection *connection;
	GHashTable      *config;
	GValue          *val;
	GError          *err = NULL;
	char            *tun_device;
	char            *resolved_hostname;

	connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, &err);
	if (!connection) {
		g_warning ("Could not get the system bus: %s", err->message);
		nm_vpn_plugin_set_state ((NMVPNPlugin*)plugin, NM_VPN_SERVICE_STATE_STOPPED);
		return FALSE;
	}

	config = g_hash_table_new (g_str_hash, g_str_equal);

	if (debug) {
		g_message ("Local TUN device: 'tun%d'", priv->io_data->local_tun_number);
		g_message ("Remote gateway: '%s'", priv->io_data->remote_gw);
		g_message ("Remote IP: '%s'", priv->io_data->remote_addr);
		g_message ("Local IP: '%s'", priv->io_data->local_addr);
		g_message ("Netmask: '%s'", priv->io_data->netmask);
	}

	// TODO handle errors better
	/* Retrieve local address */
	if (priv->io_data->local_addr != NULL)
	{
		val = addr_to_gvalue (priv->io_data->local_addr);
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS, val);
	}
	else
	{
		g_warning ("local_addr unset.");
	}

	/* Retrieve remote address */
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

	/* Retrieve remote gw address */
	if (priv->io_data->remote_gw != NULL)
	{
		/* We might have to resolve that */
		resolved_hostname = resolve_hostname (priv->io_data->remote_gw);
		val = addr_to_gvalue (resolved_hostname);
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_EXT_GATEWAY, val);
		g_free (resolved_hostname);
	}
	else
	{
		g_warning ("remote_gw unset.");
	}

	/* Retrieve tun interface */
	if (priv->io_data->local_tun_number != -1)
	{
		tun_device =
			(gpointer) g_strdup_printf ("tun%d", priv->io_data->local_tun_number);
		val = str_to_gvalue (tun_device, FALSE);
		g_free(tun_device);
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_TUNDEV, val);
	}
	else
	{
		g_warning ("local_tun_interface unset.");
	}

	/* Netmask */
	if (priv->io_data->netmask != NULL && g_str_has_prefix (priv->io_data->netmask, "255.")) {
		guint32 addr;
		val = addr_to_gvalue(priv->io_data->netmask);
		addr = g_value_get_uint (val);
		g_value_set_uint (val, nm_utils_ip4_netmask_to_prefix (addr));
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_PREFIX, val);
	} else {
		g_warning ("netmask unset.");
	}

	send_ip4_config (connection, config);
	return TRUE;
}

static gboolean
nm_ssh_local_tun_up_cb (gpointer data)
{
	NMSshPlugin *plugin = NM_SSH_PLUGIN (data);
	NMSshPluginPrivate *priv = NM_SSH_PLUGIN_GET_PRIVATE (plugin);
	NMSshPluginIOData *io_data = priv->io_data;
	char *ifconfig_cmd;

	priv->connect_count++;

	/* format the ifconfig command */
	ifconfig_cmd = (gpointer) g_strdup_printf (
		"/sbin/ifconfig tun%d %s netmask %s pointopoint %s mtu %d",
		io_data->local_tun_number,
		io_data->local_addr,
		io_data->netmask,
		io_data->remote_addr,
		priv->io_data->mtu);

	g_message ("Running: '%s'", ifconfig_cmd);

	if (system(ifconfig_cmd) != 0 &&
		priv->connect_count <= 30)
	{
		g_free(ifconfig_cmd);
		return TRUE;
	}
	g_free(ifconfig_cmd);

	g_message ("Interface tun%d configured.", io_data->local_tun_number);

	priv->connect_timer = 0;
	send_network_config(plugin);
	// Return false so we don't get called again
	return FALSE;
}


static void
nm_ssh_schedule_ifconfig_timer (NMSshPlugin *plugin)
{
	NMSshPluginPrivate *priv = NM_SSH_PLUGIN_GET_PRIVATE (plugin);

	if (priv->connect_timer == 0)
		priv->connect_timer = g_timeout_add (1000, nm_ssh_local_tun_up_cb, plugin);
}

static gboolean
nm_ssh_stdout_cb (GIOChannel *source, GIOCondition condition, gpointer user_data)
{
	NMVPNPlugin *plugin = NM_VPN_PLUGIN (user_data);
	NMSshPluginIOData *io_data = NM_SSH_PLUGIN_GET_PRIVATE (plugin)->io_data;
	char *str = NULL;

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
	if (g_str_has_prefix(str, "debug1: Requesting tun unit")) {
		sscanf(str, "debug1: Requesting tun unit %d", &io_data->remote_tun_number);
		g_message("Remote tun: %d", io_data->remote_tun_number);
		g_message(str);
	} else if (g_str_has_prefix (str, "debug1: sys_tun_open:")) {
		sscanf(str, "debug1: sys_tun_open: tun%d", &io_data->local_tun_number);
		g_message("Local tun: %d", io_data->local_tun_number);
		g_message(str);
		/* Starting timer here for getting local interface up... */
		nm_ssh_schedule_ifconfig_timer ((NMSshPlugin*)plugin);
	} else if (g_str_has_prefix (str, "Tunnel device open failed.")) {
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

static gint
nm_ssh_get_free_tun_device (void)
{
	gint tun_device;
	char *system_cmd;

	for (tun_device = 0; tun_device <= 255; tun_device++)
	{
		system_cmd = (gpointer) g_strdup_printf ("/sbin/ifconfig tun%d", tun_device);
		if (system(system_cmd) != 0)
		{
			g_free(system_cmd);
			return tun_device;
		}
		g_free(system_cmd);
	}
	return -1;
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
	if (priv->io_data && priv->io_data->ssh_stdout_channel) {
		GIOChannel *channel = priv->io_data->ssh_stdout_channel;
		GIOCondition condition;

		while ((condition = g_io_channel_get_buffer_condition (channel)) & G_IO_IN) {
			if (!nm_ssh_stdout_cb (channel, condition, plugin)) {
				good_exit = FALSE;
				break;
			}
		}
	}

	/* Try to get the last bits of data from ssh */
	if (priv->io_data && priv->io_data->ssh_stderr_channel) {
		GIOChannel *channel = priv->io_data->ssh_stderr_channel;
		GIOCondition condition;

		while ((condition = g_io_channel_get_buffer_condition (channel)) & G_IO_IN) {
			if (!nm_ssh_stdout_cb (channel, condition, plugin)) {
				good_exit = FALSE;
				break;
			}
		}
	}

	if (!good_exit)
		nm_vpn_plugin_failure (plugin, failure);

	nm_vpn_plugin_set_state (plugin, NM_VPN_SERVICE_STATE_STOPPED);
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

static void
add_ssh_extra_opts (GPtrArray *args, const char *extra_opts)
{
	gchar      **extra_opts_split;
	gchar      **iter;

	/* Needs to separate arguements nicely */
	extra_opts_split = g_strsplit (extra_opts, " ", 256);
	iter = extra_opts_split;

	/* Ensure it's a valid DNS name or IP address */
	while (*iter) {
		g_message("%s", *iter);
		add_ssh_arg (args, *iter);
		iter++;
	}
	g_strfreev (extra_opts_split);
}

static gboolean
get_ssh_arg_int (const char *arg, long int *retval)
{
	long int tmp_int;

	/* Convert -> int and back to string for security's sake since
	 * strtol() ignores some leading and trailing characters.
	 */
	errno = 0;
	tmp_int = strtol (arg, NULL, 10);
	if (errno != 0)
		return FALSE;

	*retval = tmp_int;
	return TRUE;
}

static char *
get_ssh_agent_socket (const char *directory, GError **error)
{
	/* Search a /tmp/ssh- for the agent socket and returns it */
	GFileEnumerator *enumerator;
	GFile           *ssh_dir;
	GFileInfo       *info;
	const char      *name;
	char            *ssh_socket = NULL;

	ssh_dir = g_file_new_for_path(directory);
	enumerator = g_file_enumerate_children (ssh_dir, NULL, 0, NULL, error);
	if (enumerator == NULL)
	{
		return FALSE;
	}

	/* Iterate on files in /tmp/ssh-XXXXXXXXXX directory */
	while ((info = g_file_enumerator_next_file (enumerator,
		NULL, error)) != NULL &&
		ssh_socket == NULL)
	{
		name = g_file_info_get_name (info);
		if (debug && name) {
			g_message ("Searching ssh-agent socket in name: '%s'\n", name);
		}

		/* Basically we want to find a ssh-agent associated with the given
		   user that was passed to the function */
		if (G_FILE_TYPE_SPECIAL == g_file_info_get_file_type (info) &&
			NULL != name && g_str_has_prefix(name, "agent.")) {
			/* Alright, lets get the socket file for this directory */
			ssh_socket = g_strconcat(SSH_AGENT_SOCKET_ENV_VAR, "=", directory, "/", name, NULL);
		}
		g_object_unref (info);
	}
	g_file_enumerator_close (enumerator, NULL, NULL);

	/* Return a copy of the ssh_socket variable if successful */
	if (ssh_socket)
		return g_strdup(ssh_socket);

	return NULL;
}

static gboolean
probe_ssh_agent_socket (const char *username, GError **error, char **env_ssh_sock)
{
	GFileEnumerator *enumerator;
	GFile           *ssh_agent_parent_dir;
	GFileInfo       *info;
	char            *ssh_dir_path;
	const char      *name;
	const char      *owner;

	/* iterate over /tmp/ssh-* directories */
	ssh_agent_parent_dir = g_file_new_for_path(SSH_AGENT_PARENT_DIR);
	enumerator = g_file_enumerate_children (ssh_agent_parent_dir, "standard::*,owner::user", 0, NULL, error);

	if (enumerator == NULL)
	{
		/* Handle error */
		g_warning("Error getting ssh-agent socket.");
		return FALSE;
	}

	/* Reset is just in case because it's the loop condition */
	*env_ssh_sock = NULL;

	/* Iterate on parent directory where ssh-agent will open sockets */
	while ((info = g_file_enumerator_next_file (enumerator,
		NULL, error)) != NULL &&
		*env_ssh_sock == NULL)
	{
		name = g_file_info_get_name (info);
		owner = g_file_info_get_attribute_string (info, G_FILE_ATTRIBUTE_OWNER_USER);

		if (debug && name) {
			g_message ("Searching ssh-agent socket directory: '%s'\n", name);
		}

		/* Basically we want to find a ssh-agent associated with the given
		   user that was passed to the function */
		if (G_FILE_TYPE_DIRECTORY == g_file_info_get_file_type (info) &&
			name != NULL && g_str_has_prefix (name, "ssh-") &&
				(g_strcmp0 (username, "") == 0 ||
				(owner != NULL && g_strcmp0 (owner, username) == 0)) ) {

			/* Alright, lets get the socket file for this directory */
			ssh_dir_path = g_strconcat(SSH_AGENT_PARENT_DIR, "/", name, NULL);
			*env_ssh_sock = get_ssh_agent_socket(ssh_dir_path, error);
			free(ssh_dir_path);

			if (debug && *env_ssh_sock)
				g_message("Found ssh-agent socket at: '%s'", *env_ssh_sock);
		}
		g_object_unref (info);
	}
	g_file_enumerator_close (enumerator, NULL, NULL);

	/* Return TRUE if we've found something... */
	if (*env_ssh_sock)
		return TRUE;

	return FALSE;
}

static gboolean
nm_ssh_start_ssh_binary (NMSshPlugin *plugin,
                                 NMSettingVPN *s_vpn,
                                 const char *default_username,
                                 GError **error)
{
	NMSshPluginPrivate *priv = NM_SSH_PLUGIN_GET_PRIVATE (plugin);
	const char *ssh_binary, *tmp;
	const char *remote, *port, *mtu;
	char *tmp_arg;
	char *envp[16];
	long int tmp_int;
	GPtrArray *args;
	GSource *ssh_watch;
	GPid pid;
	gint ssh_stdin_fd, ssh_stdout_fd, ssh_stderr_fd;

	/* Find ssh */
	ssh_binary = nm_find_ssh ();
	if (!ssh_binary) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
		             _("Could not find the ssh binary."));
					// TODO translation
		return FALSE;
	}

	/* Allocate io_data structure */
	priv->io_data = g_malloc0 (sizeof (NMSshPluginIOData));
  
	args = g_ptr_array_new ();
	add_ssh_arg (args, ssh_binary);

	/* We can use only root on remote machine... */
	priv->io_data->username = g_strdup("root");

	/* Get a local tun */
	priv->io_data->local_tun_number = nm_ssh_get_free_tun_device();
	if (priv->io_data->local_tun_number == -1)
	{
		g_warning("Could not assign a free tun device.");
		nm_vpn_plugin_set_state ((NMVPNPlugin*)plugin, NM_VPN_SERVICE_STATE_STOPPED);
		return FALSE;
	}

	/* Set verbose mode, we'll parse the arguments */
	add_ssh_arg (args, "-v");

	/* No password prompts, only key authentication supported... */
	add_ssh_arg (args, "-o"); add_ssh_arg (args, "NumberOfPasswordPrompts=0");

	/* only root is supported... */
	add_ssh_arg (args, "-l"); add_ssh_arg (args, priv->io_data->username);

	/* Extra SSH options */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_EXTRA_OPTS);
	if (tmp && strlen (tmp)) {
		add_ssh_extra_opts (args, tmp);
	} else {
		/* Add default extra options */
		add_ssh_extra_opts (args, NM_SSH_DEFAULT_EXTRA_OPTS);
	}

	/* Remote */
	remote = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_REMOTE);
	if (!(remote && strlen (remote))) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             _("Please set remote address."));
					// TODO add translation
		free_ssh_args (args);
		return FALSE;
	} else {
		priv->io_data->remote_gw = g_strdup(remote);
	}

	/* Port */
	port = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_PORT);
	add_ssh_arg (args, "-p");
	if (port && strlen (port)) {
		/* Range validation is done in dialog... */
		if (!get_ssh_arg_int (port, &tmp_int)) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Invalid port number '%s'."),
			             port);
			free_ssh_args (args);
			return FALSE;
		}
		add_ssh_arg (args, (gpointer) g_strdup_printf ("%d", (guint32) tmp_int));
		// TODO doesn't quit nicely
	} else {
		/* Default to SSH port 22 */
		add_ssh_arg (args, (gpointer) g_strdup_printf("%d", (guint32) NM_SSH_DEFAULT_PORT));
	}

	/* TUN MTU size */
	mtu = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_TUNNEL_MTU);
	if (mtu && strlen (mtu)) {
		/* Range validation is done in dialog... */
		if (!get_ssh_arg_int (mtu, &tmp_int)) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Invalid TUN MTU size '%s'."),
			             mtu);
			free_ssh_args (args);
			return FALSE;
		}
		priv->io_data->mtu = tmp_int;
	} else {
		/* Default MTU of 1500 */
		priv->io_data->mtu = NM_SSH_DEFAULT_MTU;
	}

	/* Remote tun device */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_REMOTE_TUN);
	if (tmp && strlen (tmp)) {
		/* Range validation is done in dialog... */
		if (!get_ssh_arg_int (tmp, &tmp_int)) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Invalid TUN device number '%s'."),
			             tmp);
						// TODO translation
			free_ssh_args (args);
			return FALSE;
		}
		priv->io_data->remote_tun_number = tmp_int;
	} else {
		/* Use tun100 by default*/
		priv->io_data->remote_tun_number = NM_SSH_DEFAULT_REMOTE_TUN;
	}

	/* Remote IP */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_REMOTE_IP);
	if (!tmp) {
		/* Insufficient data (FIXME: this should really be detected when validating the properties */
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
					// TODO Edit translation
		             _("Missing required remote IP address."));
		free_ssh_args (args);
		return FALSE;
	}
	priv->io_data->remote_addr = g_strdup(tmp);

	/* Local IP */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_LOCAL_IP);
	if (!tmp) {
		/* Insufficient data (FIXME: this should really be detected when validating the properties */
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
					// TODO Edit translation
		             _("Missing required local IP address."));
		free_ssh_args (args);
		return FALSE;
	}
	priv->io_data->local_addr = g_strdup(tmp);

	/* Netmask */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_NETMASK);
	if (!tmp) {
		/* Insufficient data (FIXME: this should really be detected when validating the properties */
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
					// TODO Edit translation
		             _("Missing required netmask."));
		free_ssh_args (args);
		return FALSE;
	}
	priv->io_data->netmask = g_strdup(tmp);

	/* The -w option, provide a remote and local tun device */
	tmp_arg = (gpointer) g_strdup_printf (
			"%d:%d", priv->io_data->local_tun_number, priv->io_data->remote_tun_number);
	add_ssh_arg (args, "-w"); add_ssh_arg (args, tmp_arg);
	g_free(tmp_arg);


	/* connect to remote */
	add_ssh_arg (args, priv->io_data->remote_gw);

	/* Command line to run on remote machine */
	tmp_arg = (gpointer) g_strdup_printf (
		"/sbin/ifconfig tun%d inet %s netmask %s pointopoint %s mtu %d",
		priv->io_data->remote_tun_number,
		priv->io_data->remote_addr,
		priv->io_data->netmask,
		priv->io_data->local_addr,
		priv->io_data->mtu);
	add_ssh_arg (args, tmp_arg);
	g_free(tmp_arg);

	/* Wrap it up */
	g_ptr_array_add (args, NULL);

	/* Set SSH_AUTH_SOCK from ssh-agent */
	// TODO find username running nm-applet
	if (!probe_ssh_agent_socket("", error, &envp[0])) {
		free_ssh_args (args);
		return FALSE;
	}
	envp[1] = NULL;

	if (debug)
		g_message ("Using ssh-agent socket: '%s'", envp[0]);

	/* Spawn with pipes */
	if (!g_spawn_async_with_pipes (NULL, (char **) args->pdata, envp,
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

	return TRUE;
}

static gboolean
real_connect (NMVPNPlugin   *plugin,
              NMConnection  *connection,
              GError       **error)
{
	NMSettingVPN *s_vpn;
	const char *user_name;

	s_vpn = NM_SETTING_VPN (nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN));
	if (!s_vpn) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_CONNECTION_INVALID,
		             "%s",
		             _("Could not process the request because the VPN connection settings were invalid."));
		return FALSE;
	}

	user_name = nm_setting_vpn_get_user_name (s_vpn);

	/* Validate the properties */
	if (!nm_ssh_properties_validate (s_vpn, error))
		return FALSE;

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

// TODO
/*	connection_type = check_need_secrets (s_vpn, &need_secrets);
	if (!connection_type) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
		             _("Invalid connection type."));
		return FALSE;
	}*/

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
		_("nm-ssh-service provides integrated SSH capability to NetworkManager."));

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
