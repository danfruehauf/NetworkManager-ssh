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
#include <pwd.h>
#include <locale.h>

#include <NetworkManager.h>

#include "nm-ssh-service.h"
#include "nm-utils.h"

#if !defined(DIST_VERSION)
# define DIST_VERSION VERSION
#endif

static gboolean debug = FALSE;
static GMainLoop *loop = NULL;

G_DEFINE_TYPE (NMSshPlugin, nm_ssh_plugin, NM_TYPE_VPN_SERVICE_PLUGIN)

#define NM_SSH_PLUGIN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SSH_PLUGIN, NMSshPluginPrivate))

typedef struct {
	char *username;
	char *password;

	/* IPv4 variables */
	char *remote_gw;
	char *local_addr;
	char *remote_addr;
	char *netmask;

	/* IPv6 variables */
	gboolean ipv6;
	char *local_addr_6;
	char *remote_addr_6;
	char *netmask_6;

	/* Replace or not the default route, the default is to replace */
	gboolean no_default_route;

	/* fds for handling input/output of the SSH process */
	GIOChannel *ssh_stdin_channel;
	GIOChannel *ssh_stdout_channel;
	GIOChannel *ssh_stderr_channel;
	guint socket_channel_stdout_eventid;
	guint socket_channel_stderr_eventid;

	/* hold local and remote tun/tap numbers
	 * dev_type can be only "tap" or "tun" */
	gchar dev_type[4];
	gint remote_dev_number;
	gint local_dev_number;
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
	{ NM_SSH_KEY_REMOTE_DEV,           G_TYPE_INT, 0, 255, FALSE },
	{ NM_SSH_KEY_TAP_DEV,              G_TYPE_BOOLEAN, 0, 0, FALSE },
	{ NM_SSH_KEY_REMOTE_USERNAME,      G_TYPE_STRING, 0, 0, FALSE },
	{ NM_SSH_KEY_NO_DEFAULT_ROUTE,     G_TYPE_BOOLEAN, 0, 0, FALSE },
	/* FIXME should fix host validation for IPv6 addresses */
	{ NM_SSH_KEY_IP_6,                 G_TYPE_BOOLEAN, 0, 0, FALSE },
	{ NM_SSH_KEY_REMOTE_IP_6,          G_TYPE_STRING, 0, 0, FALSE },
	{ NM_SSH_KEY_LOCAL_IP_6,           G_TYPE_STRING, 0, 0, FALSE },
	{ NM_SSH_KEY_NETMASK_6,            G_TYPE_STRING, 0, 0, FALSE },
	{ NM_SSH_KEY_AUTH_TYPE,            G_TYPE_STRING, 0, 0, FALSE },
	{ NM_SSH_KEY_KEY_FILE,             G_TYPE_STRING, 0, 0, FALSE },
	{ NM_SSH_KEY_PASSWORD"-flags",     G_TYPE_STRING, 0, 0, FALSE },
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
		if (!isalnum (*p) && (*p != '-') && (*p != '.') && (*p != ':'))
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
	if (!strncmp (key, NM_SETTING_NAME, strlen(NM_SETTING_NAME)))
		return;

	for (i = 0; info->table[i].name; i++) {
		ValidProperty prop = info->table[i];
		long int tmp;

		if (strncmp (prop.name, key, strlen(prop.name)))
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
			if (IS_YES(value) || !strncmp (value, NO, strlen(NO)))
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
nm_ssh_properties_validate (NMSettingVpn *s_vpn, GError **error)
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

static GVariant *
addr6_to_gvariant (const char *str)
{
	struct in6_addr temp_addr;
	GVariantBuilder builder;
	int i;

	/* Empty */
	if (!str || strlen (str) < 1)
		return NULL;

	if (inet_pton (AF_INET6, str, &temp_addr) <= 0)
		return NULL;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("ay"));
	for (i = 0; i < sizeof (temp_addr); i++)
		g_variant_builder_add (&builder, "y", ((guint8 *) &temp_addr)[i]);
	return g_variant_builder_end (&builder);
}

static GVariant *
str_to_gvariant (const char *str, gboolean try_convert)
{
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

	return g_variant_new_string (str);
}

static GVariant *
addr4_to_gvariant (const char *str)
{
	struct in_addr	temp_addr;

	/* Empty */
	if (!str || strlen (str) < 1)
		return NULL;

	if (inet_pton (AF_INET, str, &temp_addr) <= 0)
		return NULL;

	return g_variant_new_uint32 (temp_addr.s_addr);
}

static char *
resolve_hostname (const char *hostname)
{
	struct in_addr addr;
	char *ip = NULL;
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
		ip = g_strdup (hostname);
	}

	return ip;
}

static gboolean
send_network_config (NMSshPlugin *plugin)
{
	NMSshPluginPrivate *priv = NM_SSH_PLUGIN_GET_PRIVATE (plugin);
	NMSshPluginIOData  *io_data = priv->io_data;
	GVariantBuilder     config, ip4config, ip6config;
	GVariant           *val;
	char               *device;
	char               *resolved_hostname;

	g_variant_builder_init (&config, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_init (&ip4config, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_init (&ip6config, G_VARIANT_TYPE_VARDICT);

	if (debug) {
		g_message ("Local device: '%s%d'", io_data->dev_type, io_data->local_dev_number);
		g_message ("Remote gateway: '%s'", io_data->remote_gw);
		g_message ("Remote IP: '%s'", io_data->remote_addr);
		g_message ("Local IP: '%s'", io_data->local_addr);
		g_message ("Netmask: '%s'", io_data->netmask);
		if (io_data->ipv6) {
			g_message ("IPv6 Remote IP: '%s'", io_data->remote_addr_6);
			g_message ("IPv6 Local IP: '%s'", io_data->local_addr_6);
			g_message ("IPv6 Prefix: '%s'", io_data->netmask_6);
		}
	}

	/* General non IPv4 or IPv6 values (remote_gw, device, mtu) */

	/* remote_gw */
	if (io_data->remote_gw)
	{
		/* We might have to resolve that */
		resolved_hostname = resolve_hostname (io_data->remote_gw);
		if (resolved_hostname) {
			val = addr4_to_gvariant (resolved_hostname);
			g_variant_builder_add (&config, "{sv}", NM_VPN_PLUGIN_CONFIG_EXT_GATEWAY, val);
			g_free (resolved_hostname);
		} else {
			g_warning ("Could not resolve remote_gw.");
		}
	}
	else
		g_warning ("remote_gw unset.");

	/* device */
	if (io_data->local_dev_number != -1)
	{
		device =
			(gpointer) g_strdup_printf ("%s%d", io_data->dev_type, io_data->local_dev_number);
		val = str_to_gvariant (device, FALSE);
		g_free(device);
		g_variant_builder_add (&config, "{sv}", NM_VPN_PLUGIN_CONFIG_TUNDEV, val);
	}
	else
		g_warning ("local_dev_number unset.");

	/* mtu */
	if (io_data->mtu > 0)
	{
		val = str_to_gvariant (g_strdup_printf("%d", io_data->mtu), FALSE);
		g_variant_builder_add (&config, "{sv}", NM_VPN_PLUGIN_CONFIG_MTU, val);
	}
	else
		g_warning ("local_dev_number unset.");

	/* End General non IPv4 or IPv6 values */

	/* ---------------------------------------------------- */

	/* IPv4 specific (local_addr, remote_addr, netmask) */
	g_variant_builder_add (&config, "{sv}", NM_VPN_PLUGIN_CONFIG_HAS_IP4, g_variant_new_boolean (TRUE));

	/* replace default route? */
	if (io_data->no_default_route) {
		g_variant_builder_add (&config, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_NEVER_DEFAULT, g_variant_new_boolean (TRUE));
	}

	/* local_address */
	if (io_data->local_addr)
	{
		val = addr4_to_gvariant (io_data->local_addr);
		g_variant_builder_add (&ip4config, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS, val);
	}
	else
		g_warning ("local_addr unset.");

	/* remote_addr */
	if (io_data->remote_addr)
	{
		val = addr4_to_gvariant (io_data->remote_addr);
		g_variant_builder_add (&ip4config, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_INT_GATEWAY, val);
		g_variant_builder_add (&ip4config, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_PTP, val);
	}
	else
		g_warning ("remote_addr unset.");

	/* netmask */
	if (io_data->netmask && g_str_has_prefix (io_data->netmask, "255.")) {
			guint32 addr;
			val = addr4_to_gvariant(io_data->netmask);
			addr = g_variant_get_uint32 (val);
			g_variant_unref (val);
			val = g_variant_new_uint32 (nm_utils_ip4_netmask_to_prefix (addr));
			g_variant_builder_add (&ip4config, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_PREFIX, val);
	} else
		g_warning ("netmask unset.");

	/* End IPv4 specific (local_addr, remote_addr, netmask) */

	/* ---------------------------------------------------- */

	/* IPv6 specific (local_addr_6, remote_addr_6, netmask_6) */
	if (io_data->ipv6) {
		g_variant_builder_add (&config, "{sv}", NM_VPN_PLUGIN_CONFIG_HAS_IP6, g_variant_new_boolean (TRUE));

		/* replace default route? */
		if (io_data->no_default_route) {
			g_variant_builder_add (&config, "{sv}", NM_VPN_PLUGIN_IP6_CONFIG_NEVER_DEFAULT, g_variant_new_boolean (TRUE));
		}

		/* local_addr_6 */
		if (io_data->local_addr_6)
		{
			val = addr6_to_gvariant (io_data->local_addr_6);
			g_variant_builder_add (&ip6config, "{sv}", NM_VPN_PLUGIN_IP6_CONFIG_ADDRESS, val);
		}
		else
			g_warning ("local_addr_6 unset.");
	
		/* remote_addr_6 */
		if (io_data->remote_addr_6)
		{
			val = addr6_to_gvariant (io_data->remote_addr_6);
			g_variant_builder_add (&ip6config, "{sv}", NM_VPN_PLUGIN_IP6_CONFIG_INT_GATEWAY, val);
			g_variant_builder_add (&ip6config, "{sv}", NM_VPN_PLUGIN_IP6_CONFIG_PTP, val);
		}
		else
			g_warning ("remote_addr_6 unset.");
	
		/* netmask_6 */
		if (io_data->netmask_6) {
			val = g_variant_new_uint32 (strtol (io_data->netmask_6, NULL, 10));
			g_variant_builder_add (&ip6config, "{sv}", NM_VPN_PLUGIN_IP6_CONFIG_PREFIX, val);
		} else
			g_warning ("netmask_6 unset.");
	}
	
	/* End IPv6 specific (local_addr_6, remote_addr_6, netmask_6) */

	/* ---------------------------------------------------- */


	/* Send general config */
	nm_vpn_service_plugin_set_config ((NMVpnServicePlugin*) plugin,
	                                  g_variant_builder_end (&config));

	/* Send IPv6 config */
	if (io_data->ipv6)
		nm_vpn_service_plugin_set_ip6_config ((NMVpnServicePlugin*) plugin,
		                                      g_variant_builder_end (&ip6config));

	/* Send IPv4 config */
	nm_vpn_service_plugin_set_ip4_config ((NMVpnServicePlugin*) plugin,
	                                      g_variant_builder_end (&ip4config));

	return TRUE;
}

static gboolean
nm_ssh_local_device_up_cb (gpointer data)
{
	NMSshPlugin *plugin = NM_SSH_PLUGIN (data);
	NMSshPluginPrivate *priv = NM_SSH_PLUGIN_GET_PRIVATE (plugin);
	NMSshPluginIOData *io_data = priv->io_data;
	char *ifconfig_cmd_4, *ifconfig_cmd_6;

	priv->connect_count++;

	/* IPv4 ifconfig command */
	ifconfig_cmd_4 = (gpointer) g_strdup_printf (
		"%s %s%d %s netmask %s pointopoint %s mtu %d up",
		IFCONFIG,
		io_data->dev_type,
		io_data->local_dev_number,
		io_data->local_addr,
		io_data->netmask,
		io_data->remote_addr,
		priv->io_data->mtu);

	/* IPv6 ifconfig command */
	if (io_data->ipv6) {
		ifconfig_cmd_6 = (gpointer) g_strdup_printf (
			"%s %s%d add %s/%s",
			IFCONFIG,
			io_data->dev_type,
			io_data->local_dev_number,
			io_data->local_addr_6,
			io_data->netmask_6);
	} else {
		/* No IPv6, we'll just have a null command */
		ifconfig_cmd_6 = g_strdup("");
	}

	if (debug) {
		g_message ("IPv4 ifconfig: '%s'", ifconfig_cmd_4);
		g_message ("IPv6 ifconfig: '%s'", ifconfig_cmd_6);
	}

	if ((system(ifconfig_cmd_4) != 0 || system(ifconfig_cmd_6) != 0 ) &&
		priv->connect_count <= 30)
	{
		/* We failed, but we'll try again soon... */
		g_free(ifconfig_cmd_4);
		g_free(ifconfig_cmd_6);
		return TRUE;
	}
	g_free(ifconfig_cmd_4);
	g_free(ifconfig_cmd_6);

	g_message ("Interface %s%d configured.", io_data->dev_type, io_data->local_dev_number);

	priv->connect_timer = 0;
	send_network_config(plugin);

	/* Return false so we don't get called again */
	return FALSE;
}


static void
nm_ssh_schedule_ifconfig_timer (NMSshPlugin *plugin)
{
	NMSshPluginPrivate *priv = NM_SSH_PLUGIN_GET_PRIVATE (plugin);

	if (priv->connect_timer == 0)
		priv->connect_timer = g_timeout_add (1000, nm_ssh_local_device_up_cb, plugin);
}

static gboolean
nm_ssh_stdout_cb (GIOChannel *source, GIOCondition condition, gpointer user_data)
{
	NMVpnServicePlugin *plugin = NM_VPN_SERVICE_PLUGIN (user_data);
	char *str = NULL;

	if (!(condition & G_IO_IN))
		return TRUE;

	if (g_io_channel_read_line (source, &str, NULL, NULL, NULL) != G_IO_STATUS_NORMAL)
		return TRUE;

	if (strlen (str) < 1) {
		g_free(str);
		return TRUE;
	}

	/* Probe for the remote interface number */
	if (g_str_has_prefix(str, "debug1: Requesting tun unit")) {
	} else if (g_str_has_prefix(str, "debug1: Requesting tun unit")) {
		/* This message denotes the tun/tap device opening on the remote host */
	} else if (g_str_has_prefix (str, "debug1: sys_tun_open:")) {
		/* This message denotes the tun/tap device opening on the local host
		 * Starting timer here for getting local interface up... */
	} else if (g_str_has_prefix (str, "Tunnel device open failed.")) {
		/* Opening of local tun device failed... :( */
		g_warning("Tunnel device open failed.");
		nm_vpn_service_plugin_set_state (plugin, NM_VPN_SERVICE_STATE_STOPPED);
	} else if (g_str_has_prefix (str, "debug1: Sending command:")) {
		/* If we got to sending the command, it means that things are
		 * established, we should start the timer to get the local
		 * interface up... */
		if (NM_VPN_SERVICE_STATE_STOPPED != nm_vpn_service_plugin_get_state (plugin))
			nm_ssh_schedule_ifconfig_timer ((NMSshPlugin*)plugin);
		else if(debug)
			g_message("Not starting local timer because plugin is in STOPPED state");
	} else if (g_str_has_prefix (str, "debug1: Remote: Server has rejected tunnel device forwarding")) {
		/* Opening of remote tun device failed... :( */
		g_warning("Tunnel device open failed on remote server.");
		g_warning("Make sure you have privileges to open tun/tap devices and that your SSH server is configured with 'PermitTunnel=yes'");
		nm_vpn_service_plugin_set_state (plugin, NM_VPN_SERVICE_STATE_STOPPED);
	} else if (g_str_has_prefix (str, "debug1: Remote: Failed to open the tunnel device.")) {
		/* Opening of remote tun device failed... device busy? */
		g_warning("Tunnel device open failed on remote server.");
		g_warning("Is this device free on the remote host?");
		nm_vpn_service_plugin_set_state (plugin, NM_VPN_SERVICE_STATE_STOPPED);
	} else if (strncmp (str, "The authenticity of host", 24) == 0) {
		/* User will have to accept this new host with its fingerprint */
		g_warning("It is not a known host, continue connecting?");
		nm_vpn_service_plugin_set_state (plugin, NM_VPN_SERVICE_STATE_STOPPED);
	}

	g_message("%s", str);

	g_free(str);
	return TRUE;
}

static gint
nm_ssh_get_free_device (const char *device_type)
{
	gint device;
	char *system_cmd;

	for (device = 0; device <= 255; device++)
	{
		system_cmd = (gpointer) g_strdup_printf ("%s %s%d >& /dev/null", IFCONFIG, device_type, device);
		if (system(system_cmd) != 0)
		{
			g_free(system_cmd);
			return device;
		}
		g_free(system_cmd);
	}
	return -1;
}

static void
ssh_watch_cb (GPid pid, gint status, gpointer user_data)
{
	NMVpnServicePlugin *plugin = NM_VPN_SERVICE_PLUGIN (user_data);
	NMSshPluginPrivate *priv = NM_SSH_PLUGIN_GET_PRIVATE (plugin);
	NMVpnPluginFailure failure = NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED;
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

	if (0 != priv->connect_timer) {
		g_source_remove(priv->connect_timer);
		priv->connect_timer = 0;
	}

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
	g_source_remove(priv->io_data->socket_channel_stdout_eventid);
	close (g_io_channel_unix_get_fd(priv->io_data->ssh_stdout_channel));

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
	g_source_remove(priv->io_data->socket_channel_stderr_eventid);
	close (g_io_channel_unix_get_fd(priv->io_data->ssh_stderr_channel));

	if (!good_exit)
		nm_vpn_service_plugin_failure (plugin, failure);

	nm_vpn_service_plugin_set_state (plugin, NM_VPN_SERVICE_STATE_STOPPED);
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

/* FIXME refactor this with nm_find_ssh */
static const char *
nm_find_sshpass (void)
{
	static const char *sshpass_binary_paths[] = {
		"/usr/bin/sshpass",
		"/bin/sshpass",
		"/usr/local/bin/sshpass",
		NULL
	};
	const char  **sshpass_binary = sshpass_binary_paths;

	while (*sshpass_binary != NULL) {
		if (g_file_test (*sshpass_binary, G_FILE_TEST_EXISTS))
			break;
		sshpass_binary++;
	}

	return *sshpass_binary;
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

static char*
get_known_hosts_file(const char *username,
	const char* ssh_agent_socket)
{
	struct stat info;
	struct passwd *pw = NULL;
	char *ssh_known_hosts = NULL;
	
	/* Probe by passed username */
	if (username) {
		pw = getpwnam(username);
	/* Probe by passed ssh-agent socket ownership */
	} else if (ssh_agent_socket) {
		if (0 == stat(ssh_agent_socket, &info)) {
			pw = getpwuid(info.st_uid);
		} else {
			g_warning("Error getting ssh-agent socket ownership: %d", errno);
		}
	}

	/* FIXME Check if provided SSH_KNOWN_HOSTS_PATH really exists */
	if (pw) {
		ssh_known_hosts = g_strdup_printf("%s/%s", pw->pw_dir, SSH_KNOWN_HOSTS_PATH);
		if (0 != stat(ssh_known_hosts, &info)) {
			g_warning("No known_hosts at '%s': %d.", ssh_known_hosts, errno);
			g_free(ssh_known_hosts);
		}
	}

	return ssh_known_hosts;
}

static gboolean
nm_ssh_start_ssh_binary (NMSshPlugin *plugin,
	NMSettingVpn *s_vpn,
	const char *default_username,
	GError **error)
{
	/* This giant function is basically taking care of passing all the
	 * correct parameters to ssh (and sshpass) */
	NMSshPluginPrivate *priv = NM_SSH_PLUGIN_GET_PRIVATE (plugin);
	const char *ssh_binary, *sshpass_binary, *tmp;
	const char *remote, *port, *mtu, *ssh_agent_socket, *auth_type;
	char *known_hosts_file;
	char *tmp_arg;
	char *ifconfig_cmd_4, *ifconfig_cmd_6;
	char *envp[16];
	long int tmp_int;
	GPtrArray *args;
	GSource *ssh_watch;
	GPid pid;
	gint ssh_stdin_fd, ssh_stdout_fd, ssh_stderr_fd;
	int sshpass_pipe[2];
	const gchar *password = NULL;

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

	/* Allocate io_data structure */
	priv->io_data = g_malloc0 (sizeof (NMSshPluginIOData));

	args = g_ptr_array_new ();

	/* Get auth_type from s_vpn */
	auth_type = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_AUTH_TYPE);

	/* Handle different behaviour for different auth types */
	envp[0] = NULL;
	if (!strncmp (auth_type, NM_SSH_AUTH_TYPE_PASSWORD, strlen(NM_SSH_AUTH_TYPE_PASSWORD))) {
		/* If the user wishes to supply a password */

		/* Find sshpass, we'll use it to wrap ssh and provide a password from
	 	* the command line */
		sshpass_binary = nm_find_sshpass ();
		if (!sshpass_binary) {
			g_set_error (error,
		                 NM_VPN_PLUGIN_ERROR,
		                 NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		                 "%s",
		                 _("Could not find the sshpass binary."));
			return FALSE;
		}

		/* Use sshpass binary */
		add_ssh_arg (args, sshpass_binary);

		/* Get password */
		password = nm_setting_vpn_get_secret (s_vpn, NM_SSH_KEY_PASSWORD);
		if (password && strlen(password)) {
			if (pipe(sshpass_pipe))
			{
				g_set_error (
					error,
					NM_VPN_PLUGIN_ERROR,
					NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
					"%s",
					_("Failed creating pipe."));
				free_ssh_args (args);
				return FALSE;
			}
			tmp = (gpointer) g_strdup_printf ("-d%d", sshpass_pipe[0]);
			add_ssh_arg (args, tmp);
			g_free((gpointer) tmp);
		} else {
			/* No password specified? Exit! */
			g_set_error (
				error,
				NM_VPN_PLUGIN_ERROR,
				NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
				"%s",
				_("No password specified."));
			free_ssh_args (args);
			return FALSE;
		}

		/* And add the ssh_binary */
		add_ssh_arg (args, ssh_binary);

		/* Prompt just once for password, it's enough */
		add_ssh_arg (args, "-o"); add_ssh_arg (args, "NumberOfPasswordPrompts=1");
		add_ssh_arg (args, "-o"); add_ssh_arg (args, "PreferredAuthentications=password");

	} else {
		/* Add the ssh binary, as we're not going to use sshpass */
		add_ssh_arg (args, ssh_binary);

		/* No password prompts, only key authentication if user specifies
		 * key of ssh agent auth */
		add_ssh_arg (args, "-o"); add_ssh_arg (args, "NumberOfPasswordPrompts=0");
		add_ssh_arg (args, "-o"); add_ssh_arg (args, "PreferredAuthentications=publickey");

		/* Passing a id_dsa/id_rsa key as an argument to ssh */
		if (!strncmp (auth_type, NM_SSH_AUTH_TYPE_KEY, strlen(NM_SSH_AUTH_TYPE_KEY))) {
			tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_KEY_FILE);
			if (tmp && strlen (tmp)) {
				/* Specify key file */
				add_ssh_arg (args, "-i");
				add_ssh_arg (args, tmp);
			} else {
				/* No key specified? Exit! */
				g_set_error (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		                     "%s",
		                     _("Key authentication selected, but no key file specified."));
				free_ssh_args (args);
				return FALSE;
			}
		} else if (!strncmp (auth_type, NM_SSH_AUTH_TYPE_SSH_AGENT, strlen(NM_SSH_AUTH_TYPE_SSH_AGENT))) {
			/* Last but not least, the original nm-ssh default behaviour which
		 	* which is the sanest of all - SSH_AGENT socket */
			/* FIXME add all the ssh agent logic here */
			/* Set SSH_AUTH_SOCK from ssh-agent
	 		* Passes as a secret key from the user's context
	 		* using auth-dialog */
			ssh_agent_socket = nm_setting_vpn_get_secret (s_vpn, NM_SSH_KEY_SSH_AUTH_SOCK);
			if (ssh_agent_socket && strlen(ssh_agent_socket)) {
				envp[0] = (gpointer) g_strdup_printf ("%s=%s", SSH_AUTH_SOCK, ssh_agent_socket);
			} else {
				/* No SSH_AUTH_SOCK passed from user context */
				g_set_error (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		                     "%s",
		                     _("Missing required SSH_AUTH_SOCK."));
				free_ssh_args (args);
				return FALSE;
			}
			envp[1] = NULL;

			if (debug)
				g_message ("Using ssh-agent socket: '%s'", envp[0]);

		} else {
			g_set_error (
				error,
				NM_VPN_PLUGIN_ERROR,
				NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
				_("Unknown authentication type: %s."), auth_type);
			free_ssh_args (args);
			return FALSE;
		}
	}

	/* Set verbose mode, we'll parse the arguments */
	add_ssh_arg (args, "-v");

	/* Dictate whether to replace the default route or not */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_NO_DEFAULT_ROUTE);
	if (tmp && IS_YES(tmp)) {
		priv->io_data->no_default_route = TRUE;
	} else {
		/* That's the default - to replace the default route
		   It's a VPN after all!! :) */
		priv->io_data->no_default_route = FALSE;
	}

	/* FIXME if not using SSH_AUTH_SOCK we can't know where is known_hosts */
	/* We have SSH_AUTH_SOCK, we'll assume it's owned by the user
	 * that we should use its .ssh/known_hosts file
	 * So we'll probe the user owning SSH_AUTH_SOCK and then use
	 * -o UserKnownHostsFile=$HOME/.ssh/known_hosts */
	known_hosts_file = get_known_hosts_file(default_username, ssh_agent_socket);
	if (!(known_hosts_file && strlen (known_hosts_file))) {
		g_warning("Using root's .ssh/known_hosts");
	} else {
		if (debug)
			g_message("Using known_hosts at: '%s'", known_hosts_file);
		add_ssh_arg (args, "-o");
		add_ssh_arg (args, g_strdup_printf("UserKnownHostsFile=%s", known_hosts_file) );
		g_free(known_hosts_file);
	}

	/* Extra SSH options */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_EXTRA_OPTS);
	if (tmp && strlen (tmp)) {
		add_ssh_extra_opts (args, tmp);
	} else {
		/* Add default extra options */
		add_ssh_extra_opts (args, NM_SSH_DEFAULT_EXTRA_OPTS);
	}

	/* Device, either tun or tap */
	add_ssh_arg (args, "-o");
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_TAP_DEV);
	if (tmp && IS_YES(tmp)) {
		add_ssh_arg (args, "Tunnel=ethernet");
		g_strlcpy ((gchar *) &priv->io_data->dev_type, "tap", 4);
	} else {
		add_ssh_arg (args, "Tunnel=point-to-point");
		g_strlcpy ((gchar *) &priv->io_data->dev_type, "tun", 4);
	}

	/* Get a local tun/tap */
	priv->io_data->local_dev_number = nm_ssh_get_free_device(priv->io_data->dev_type);
	if (priv->io_data->local_dev_number == -1)
	{
		g_warning("Could not assign a free tun/tap device.");
		nm_vpn_service_plugin_set_state ((NMVpnServicePlugin*)plugin, NM_VPN_SERVICE_STATE_STOPPED);
		return FALSE;
	}

	/* Remote */
	remote = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_REMOTE);
	if (!(remote && strlen (remote))) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             _("Please set remote address."));
		free_ssh_args (args);
		return FALSE;
	} else {
		priv->io_data->remote_gw = g_strdup(remote);
	}

	/* Port */
	port = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_PORT);
	add_ssh_arg (args, "-o");
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
		add_ssh_arg (args, (gpointer) g_strdup_printf ("Port=%d", (guint32) tmp_int));
	} else {
		/* Default to SSH port 22 */
		add_ssh_arg (args, (gpointer) g_strdup_printf("Port=%d", (guint32) NM_SSH_DEFAULT_PORT));
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

	/* Remote device */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_REMOTE_DEV);
	if (tmp && strlen (tmp)) {
		/* Range validation is done in dialog... */
		if (!get_ssh_arg_int (tmp, &tmp_int)) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Invalid TUN/TAP device number '%s'."),
			             tmp);
			free_ssh_args (args);
			return FALSE;
		}
		priv->io_data->remote_dev_number = tmp_int;
	} else {
		/* Use tun100/tap100 by default */
		priv->io_data->remote_dev_number = NM_SSH_DEFAULT_REMOTE_DEV;
	}

	/* Remote IP */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_REMOTE_IP);
	if (!tmp) {
		/* Insufficient data (FIXME: this should really be detected when validating the properties */
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
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
		             _("Missing required local IP address."));
		free_ssh_args (args);
		return FALSE;
	}
	priv->io_data->local_addr = g_strdup(tmp);

	/* Netmask */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_NETMASK);
	if (!tmp) {
		priv->io_data->netmask = g_strdup(tmp);

		/* Insufficient data (FIXME: this should really be detected when validating the properties */
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
		             _("Missing required netmask."));
		free_ssh_args (args);
		return FALSE;
	}
	priv->io_data->netmask = g_strdup(tmp);

	/* IPv6 enabled? */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_IP_6);
	if (tmp && IS_YES(tmp)) {
		/* IPv6 is enabled */
		priv->io_data->ipv6 = TRUE;
		
		/* Remote IP IPv6 */
		tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_REMOTE_IP_6);
		if (!tmp) {
			/* Insufficient data (FIXME: this should really be detected when validating the properties */
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             "%s",
			             _("Missing required IPv6 remote IP address."));
			free_ssh_args (args);
			return FALSE;
		}
		priv->io_data->remote_addr_6 = g_strdup(tmp);
	
		/* Local IP IPv6 */
		tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_LOCAL_IP_6);
		if (!tmp) {
			/* Insufficient data (FIXME: this should really be detected when validating the properties */
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             "%s",
			             _("Missing required IPv6 local IP address."));
			free_ssh_args (args);
			return FALSE;
		}
		priv->io_data->local_addr_6 = g_strdup(tmp);
	
		/* Prefix IPv6 */
		tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_NETMASK_6);
		if (!tmp) {
			/* Insufficient data (FIXME: this should really be detected when validating the properties */
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             "%s",
			             _("Missing required IPv6 netmask."));
			free_ssh_args (args);
			return FALSE;
		}
		priv->io_data->netmask_6 = g_strdup(tmp);
	} else {
		/* Set the values so they are not NULL */
		priv->io_data->ipv6 = FALSE;
		priv->io_data->remote_addr_6 = g_strdup("");
		priv->io_data->local_addr_6 = g_strdup("");
		priv->io_data->netmask_6 = g_strdup("");
	}


	/* The -w option, provide a remote and local tun/tap device */
	tmp_arg = (gpointer) g_strdup_printf (
			"TunnelDevice=%d:%d", priv->io_data->local_dev_number, priv->io_data->remote_dev_number);
	add_ssh_arg (args, "-o"); add_ssh_arg (args, tmp_arg);
	g_free(tmp_arg);

	/* Remote username, should usually be root */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_REMOTE_USERNAME);
	if (tmp && strlen (tmp)) {
		priv->io_data->username = g_strdup (tmp);
	} else {
		/* Add default username - root */
		priv->io_data->username = g_strdup (NM_SSH_DEFAULT_REMOTE_USERNAME);
	}
	tmp_arg = g_strdup_printf ("User=%s", priv->io_data->username);
	add_ssh_arg (args, "-o");
	add_ssh_arg (args, tmp_arg);
	g_free(tmp_arg);

	/* Connect to remote */
	tmp_arg = g_strdup_printf ("HostName=%s", priv->io_data->remote_gw);
	add_ssh_arg (args, "-o");
	add_ssh_arg (args, tmp_arg);
	g_free(tmp_arg);

	/* This is supposedly the hostname parameter, but we can pass anything
	 * as we passed '-o Hostname=' before that */
	add_ssh_arg (args, "NetworkManager-ssh");

	/* Command line to run on remote machine */
	ifconfig_cmd_4 = (gpointer) g_strdup_printf (
		"%s %s%d inet %s netmask %s pointopoint %s mtu %d",
		IFCONFIG,
		priv->io_data->dev_type,
		priv->io_data->remote_dev_number,
		priv->io_data->remote_addr,
		priv->io_data->netmask,
		priv->io_data->local_addr,
		priv->io_data->mtu);

	/* IPv6 ifconfig command to run on remote machine */
	if (priv->io_data->ipv6) {
		ifconfig_cmd_6 = (gpointer) g_strdup_printf (
			"%s %s%d add %s/%s",
			IFCONFIG,
			priv->io_data->dev_type,
			priv->io_data->remote_dev_number,
			priv->io_data->remote_addr_6,
			priv->io_data->netmask_6);
	} else {
		ifconfig_cmd_6 = g_strdup("");
	}
	/* Concatenate ifconfig_cmd_4 and ifconfig_cmd_6 to one command */
	tmp_arg = g_strconcat(ifconfig_cmd_4, "; ", ifconfig_cmd_6, NULL);
	add_ssh_arg (args, tmp_arg);
	g_free(ifconfig_cmd_4);
	g_free(ifconfig_cmd_6);
	g_free(tmp_arg);

	/* Wrap it up */
	g_ptr_array_add (args, NULL);

	/* Spawn with pipes */
	if (!g_spawn_async_with_pipes (NULL, (char **) args->pdata, envp,
						G_SPAWN_DO_NOT_REAP_CHILD | G_SPAWN_LEAVE_DESCRIPTORS_OPEN, NULL, NULL, &pid,
						&ssh_stdin_fd, &ssh_stdout_fd, &ssh_stderr_fd,
						error)) {
		free_ssh_args (args);
		return FALSE;
	}
	free_ssh_args (args);

	/* Write password to fd, so sshpass can pick it up */
	if (!strncmp (auth_type, NM_SSH_AUTH_TYPE_PASSWORD, strlen(NM_SSH_AUTH_TYPE_PASSWORD))) {
		tmp_arg = g_strdup_printf ("%s\n", password);
		if (write(sshpass_pipe[1], tmp_arg, strlen(tmp_arg)) != strlen(tmp_arg)) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             "%s",
			             _("Could not pass password to sshpass."));
			free_ssh_args (args);
			g_free(tmp_arg);
			return FALSE;
		}

		g_free(tmp_arg);
		close(sshpass_pipe[0]);
		close(sshpass_pipe[1]);
	}

	g_message ("ssh started with pid %d", pid);

	/* Add a watch for the SSH stdout and stderr */
	priv->io_data->ssh_stdin_channel = g_io_channel_unix_new (ssh_stdin_fd);
	priv->io_data->ssh_stdout_channel = g_io_channel_unix_new (ssh_stdout_fd);
	priv->io_data->ssh_stderr_channel = g_io_channel_unix_new (ssh_stderr_fd);

	/* Set io watches on stdout and stderr */
	/* stdout */
	priv->io_data->socket_channel_stdout_eventid = g_io_add_watch (
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
validate_ssh_agent_socket(const char* ssh_agent_socket, GError **error)
{
	GFile           *gfile = NULL;
	GFileInfo       *info = NULL;
	if (debug)
		g_message ("Inspecing ssh agent socket at: '%s'\n", ssh_agent_socket);

	if (!g_file_test (ssh_agent_socket, G_FILE_TEST_EXISTS))
		return FALSE;

	gfile = g_file_new_for_path(ssh_agent_socket);
	if (!gfile)
		return FALSE;

	info = g_file_query_info (gfile, "standard::*,owner::user", 0, NULL, error);
	if (info && G_FILE_TYPE_SPECIAL == g_file_info_get_file_type (info)) {
		g_message ("Found ssh agent socket at: '%s'\n", ssh_agent_socket);
		return TRUE;
	}

	return FALSE;
}

static gboolean
real_connect (NMVpnServicePlugin   *plugin,
	NMConnection  *connection,
	GError       **error)
{
	NMSettingVpn *s_vpn;
	const char *user_name;

	s_vpn = NM_SETTING_VPN (nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN));
	if (!s_vpn) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
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
real_need_secrets (NMVpnServicePlugin *plugin,
	NMConnection *connection,
	const char **setting_name,
	GError **error)
{
	NMSettingVpn *s_vpn;
	gboolean need_secrets = FALSE;
	const char *auth_type = NULL;
	NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;

	g_return_val_if_fail (NM_IS_VPN_SERVICE_PLUGIN (plugin), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	if (debug) {
		g_message ("%s: connection -------------------------------------", __func__);
		nm_connection_dump (connection);
	}

	s_vpn = NM_SETTING_VPN (nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN));
	if (!s_vpn) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
		             "%s",
		             _("Could not process the request because the VPN connection settings were invalid."));
		return FALSE;
	}

	/* Get auth_type from s_vpn */
	auth_type = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_AUTH_TYPE);
	if (!auth_type)
		auth_type = NM_SSH_AUTH_TYPE_SSH_AGENT;

	/* Lets see if we need some passwords... */
	if (!strncmp (auth_type, NM_SSH_AUTH_TYPE_PASSWORD, strlen(NM_SSH_AUTH_TYPE_PASSWORD))) {
		/* Password auth */
		need_secrets = TRUE;
		nm_setting_get_secret_flags (NM_SETTING (s_vpn), NM_SSH_KEY_PASSWORD, &flags, NULL);

		/* If the password is saved and we can retrieve it, it's not required */
		if (nm_setting_vpn_get_secret (NM_SETTING_VPN (s_vpn), NM_SSH_KEY_PASSWORD)) {
			need_secrets = FALSE;
		}
	} else if (!strncmp (auth_type, NM_SSH_AUTH_TYPE_KEY, strlen(NM_SSH_AUTH_TYPE_KEY))) {
		/* FIXME check if key file needs a password */
		need_secrets = FALSE;
	} else if (!strncmp (auth_type, NM_SSH_AUTH_TYPE_SSH_AGENT, strlen(NM_SSH_AUTH_TYPE_SSH_AGENT))) {
		/* If we don't have our SSH_AUTH_SOCK set, we need it
		 * SSH_AUTH_SOCK is passed as a secret only because it has to come
		 * from a user's context and this plugin will run as root... */
		const gchar *ssh_agent_socket = NULL;
		ssh_agent_socket = nm_setting_vpn_get_secret (s_vpn, NM_SSH_KEY_SSH_AUTH_SOCK);
		if (ssh_agent_socket && validate_ssh_agent_socket (ssh_agent_socket, error)) {
			need_secrets = FALSE;
		} else {
			need_secrets = TRUE;
		}
	} else {
		g_set_error (
			error,
			NM_VPN_PLUGIN_ERROR,
			NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			_("Unknown authentication type: %s."), auth_type);
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
real_disconnect (NMVpnServicePlugin	 *plugin,
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
	NMVpnServicePluginClass *parent_class = NM_VPN_SERVICE_PLUGIN_CLASS (plugin_class);

	g_type_class_add_private (object_class, sizeof (NMSshPluginPrivate));

	/* virtual methods */
	parent_class->connect      = real_connect;
	parent_class->need_secrets = real_need_secrets;
	parent_class->disconnect   = real_disconnect;
}

static void
plugin_state_changed (NMSshPlugin *plugin,
	NMVpnServiceState state,
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
	                                            NM_VPN_SERVICE_PLUGIN_DBUS_SERVICE_NAME,
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
quit_mainloop (NMVpnServicePlugin *plugin, gpointer user_data)
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

#if !GLIB_CHECK_VERSION (2, 35, 3)
	g_type_init ();
#endif

	/* locale will be set according to environment LC_* variables */
	setlocale (LC_ALL, "");

	bindtextdomain (GETTEXT_PACKAGE, NM_SSH_LOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);

	/* Parse options */
	opt_ctx = g_option_context_new (NULL);
	g_option_context_set_translation_domain (opt_ctx, GETTEXT_PACKAGE);
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
