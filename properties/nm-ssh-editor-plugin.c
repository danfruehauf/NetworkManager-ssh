/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 *
 * Copyright (C) 2013 Dan Fruehauf, <malkodan@gmail.com>
 * Copyright (C) 2022 Red Hat, Inc.
 * Based on work by Dan Williams, <dcbw@redhat.com>
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
 **************************************************************************/

#include "nm-default.h"
#include "nm-ssh-editor-plugin.h"

#ifdef NM_VPN_OLD
#include "nm-ssh-editor.h"
#else
#include "nm-utils/nm-vpn-plugin-utils.h"
#endif

#define SSH_PLUGIN_NAME    _("SSH")
#define SSH_PLUGIN_DESC    _("Compatible with the SSH server.")
#define SSH_PLUGIN_SERVICE NM_DBUS_SERVICE_SSH

#define PARSE_IMPORT_KEY(IMPORT_KEY, NM_SSH_KEY, ITEMS, VPN_CONN) \
if (!strncmp (ITEMS[0], IMPORT_KEY, strlen (ITEMS[0]))) { \
	nm_setting_vpn_add_data_item (VPN_CONN, NM_SSH_KEY, ITEMS[1]); \
	g_free(ITEMS); \
	continue; \
}

#define PARSE_IMPORT_KEY_BOOL(IMPORT_KEY, NM_SSH_KEY, ITEMS, VPN_CONN, VALUE) \
if (!strncmp (ITEMS[0], IMPORT_KEY, strlen (ITEMS[0]))) { \
	if (!strncmp(ITEMS[1], VALUE, strlen(ITEMS[1]))) { \
		g_message("%s=%s", NM_SSH_KEY, ITEMS[1]); \
		nm_setting_vpn_add_data_item (VPN_CONN, NM_SSH_KEY, YES); \
	} \
	g_free (ITEMS); \
	continue; \
}

#define PARSE_IMPORT_KEY_WITH_DEFAULT_VALUE_STR(IMPORT_KEY, NM_SSH_KEY, ITEMS, VPN_CONN, DEFAULT_VALUE) \
if (!strncmp (ITEMS[0], IMPORT_KEY, strlen (ITEMS[0]))) { \
	if (strncmp(ITEMS[1], DEFAULT_VALUE, strlen(ITEMS[1]))) \
		nm_setting_vpn_add_data_item (VPN_CONN, NM_SSH_KEY, ITEMS[1]); \
	g_free (ITEMS); \
	continue; \
}

#define PARSE_IMPORT_KEY_WITH_DEFAULT_VALUE_INT(IMPORT_KEY, NM_SSH_KEY, ITEMS, VPN_CONN, DEFAULT_VALUE) \
if (!strncmp (ITEMS[0], IMPORT_KEY, strlen (ITEMS[0]))) { \
	char *tmp = g_strdup_printf("%d", DEFAULT_VALUE); \
	if (strncmp(ITEMS[1], tmp, strlen(ITEMS[1]))) \
		nm_setting_vpn_add_data_item (VPN_CONN, NM_SSH_KEY, ITEMS[1]); \
	g_free (ITEMS); \
	g_free (tmp); \
	continue; \
}

enum {
	PROP_0,
	PROP_NAME,
	PROP_DESC,
	PROP_SERVICE
};

static void ssh_editor_plugin_interface_init (NMVpnEditorPluginInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (SshEditorPlugin, ssh_editor_plugin, G_TYPE_OBJECT, 0,
						G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_EDITOR_PLUGIN,
											   ssh_editor_plugin_interface_init))

static NMConnection *
import (NMVpnEditorPlugin *iface, const char *path, GError **error)
{
	NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	char *contents = NULL;
	char **lines = NULL;
	char *ext;
	char **line;

	ext = strrchr (path, '.');
	if (!ext) {
		g_set_error (error,
		             NMV_EDITOR_PLUGIN_ERROR,
		             NMV_EDITOR_PLUGIN_ERROR_FAILED,
		             "unknown SSH file extension, should be .sh");
		goto out;
	}

	if (strncmp (ext, ".sh", strlen(".sh"))) {
		g_set_error (error,
		             NMV_EDITOR_PLUGIN_ERROR,
		             NMV_EDITOR_PLUGIN_ERROR_FAILED,
		             "unknown SSH file extension, should be .sh");
		goto out;
	}

	if (!g_file_get_contents (path, &contents, NULL, error))
		return NULL;

	if (!g_utf8_validate (contents, -1, NULL)) {
		char *tmp;
		GError *conv_error = NULL;

		tmp = g_locale_to_utf8 (contents, -1, NULL, NULL, &conv_error);
		if (conv_error) {
			/* ignore the error, we tried at least. */
			g_error_free (conv_error);
			g_free (tmp);
		} else {
			g_assert (tmp);
			g_free (contents);
			contents = tmp;  /* update contents with the UTF-8 safe text */
		}
	}

	lines = g_strsplit_set (contents, "\r\n", 0);
	if (g_strv_length (lines) <= 1) {
		g_set_error (error,
		             NMV_EDITOR_PLUGIN_ERROR,
		             NMV_EDITOR_PLUGIN_ERROR_FAILED,
		             "not a valid SSH configuration file");
		goto out;
	}

	connection = nm_simple_connection_new ();
	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());

	g_object_set (s_vpn, NM_SETTING_VPN_SERVICE_TYPE, NM_DBUS_SERVICE_SSH, NULL);

	for (line = lines; *line; line++) {
		char *comment;
		char **items = NULL;

		if ((comment = strchr (*line, '#')))
			*comment = '\0';
		if ((comment = strchr (*line, ';')))
			*comment = '\0';
		if (!strlen (*line))
			continue;

		items = g_strsplit_set (*line, "=", 0);
		if (!items) {
			continue;
		} else {
			/* Uncomment if you'd like to debug parsing of items */
			/* g_message("%s = %s", items[0], items[1]); */
		}

		/* the PARSE_IMPORT_KEY will save heaps of lines of code, it's
		 * on the top of the file if you're looking for it */
		PARSE_IMPORT_KEY (REMOTE_KEY, NM_SSH_KEY_REMOTE, items, s_vpn)
		PARSE_IMPORT_KEY_WITH_DEFAULT_VALUE_STR (AUTH_TYPE_KEY, NM_SSH_KEY_AUTH_TYPE, items, s_vpn, NM_SSH_AUTH_TYPE_SSH_AGENT)
		PARSE_IMPORT_KEY_WITH_DEFAULT_VALUE_STR (REMOTE_USERNAME_KEY, NM_SSH_KEY_REMOTE_USERNAME, items, s_vpn, NM_SSH_DEFAULT_REMOTE_USERNAME);
		PARSE_IMPORT_KEY(SOCKS_ONLY_INTERFACE, NM_SSH_KEY_SOCKS_ONLY_INTERFACE, items, s_vpn);
		PARSE_IMPORT_KEY(SOCKS_BIND_ADDRESS, NM_SSH_KEY_SOCKS_BIND_ADDRESS, items, s_vpn);
		PARSE_IMPORT_KEY (KEY_FILE_KEY, NM_SSH_KEY_KEY_FILE, items, s_vpn)
		PARSE_IMPORT_KEY (REMOTE_IP_KEY, NM_SSH_KEY_REMOTE_IP, items, s_vpn)
		PARSE_IMPORT_KEY (LOCAL_IP_KEY, NM_SSH_KEY_LOCAL_IP, items, s_vpn)
		PARSE_IMPORT_KEY (NETMASK_KEY, NM_SSH_KEY_NETMASK, items, s_vpn)
		PARSE_IMPORT_KEY (IP_6_KEY, NM_SSH_KEY_IP_6, items, s_vpn)
		PARSE_IMPORT_KEY (REMOTE_IP_6_KEY, NM_SSH_KEY_REMOTE_IP_6, items, s_vpn)
		PARSE_IMPORT_KEY (LOCAL_IP_6_KEY, NM_SSH_KEY_LOCAL_IP_6, items, s_vpn)
		PARSE_IMPORT_KEY (NETMASK_6_KEY, NM_SSH_KEY_NETMASK_6, items, s_vpn)
		PARSE_IMPORT_KEY_WITH_DEFAULT_VALUE_INT (PORT_KEY, NM_SSH_KEY_PORT, items, s_vpn, NM_SSH_DEFAULT_PORT)
		PARSE_IMPORT_KEY_WITH_DEFAULT_VALUE_INT (MTU_KEY, NM_SSH_KEY_TUNNEL_MTU, items, s_vpn, NM_SSH_DEFAULT_MTU)
		PARSE_IMPORT_KEY_WITH_DEFAULT_VALUE_INT (REMOTE_DEV_KEY, NM_SSH_KEY_REMOTE_DEV, items, s_vpn, NM_SSH_DEFAULT_REMOTE_DEV)
		PARSE_IMPORT_KEY_BOOL (DEV_TYPE_KEY, NM_SSH_KEY_TAP_DEV, items, s_vpn, "tap")
	}

	if (connection)
		nm_connection_add_setting (connection, NM_SETTING (s_vpn));
	else if (s_vpn)
		g_object_unref (s_vpn);

out:
	if (lines)
		g_strfreev (lines);
	g_free (contents);
	return connection;
}

static gboolean
export (NMVpnEditorPlugin *iface,
        const char *path,
        NMConnection *connection,
        GError **error)
{
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	FILE *f;
	const char *value;
	const char *auth_type = NULL;
	const char *key_file = NULL;
	const char *gateway = NULL;
	const char *port = NULL;
	const char *local_ip = NULL;
	const char *remote_ip = NULL;
	const char *netmask = NULL;
	const char *local_ip_6 = NULL;
	const char *remote_ip_6 = NULL;
	const char *netmask_6 = NULL;
	const char *remote_dev = NULL;
	const char *mtu = NULL;
	const char *remote_username = NULL;
	const char *socks_only_interface = NULL;
	const char *socks_bind_address = NULL;
	char *device_type = NULL;
	char *tunnel_type = NULL;
	char *ifconfig_cmd_local_6 = NULL;
	char *ifconfig_cmd_remote_6 = NULL;
	char *preferred_authentication = NULL;
	unsigned password_prompt_nr = 0;
	gboolean ipv6 = FALSE;
	gboolean success = FALSE;

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_con);

	s_vpn = (NMSettingVpn *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);

	f = fopen (path, "w");
	if (!f) {
		g_set_error (error, 0, 0, "could not open file for writing");
		return FALSE;
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_REMOTE);
	if (value && strlen (value))
		gateway = value;
	else {
		g_set_error (error, 0, 0, "connection was incomplete (missing gateway)");
		goto done;
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_REMOTE_IP);
	if (value && strlen (value))
		remote_ip = value;
	else {
		g_set_error (error, 0, 0, "connection was incomplete (missing remote IP)");
		goto done;
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_LOCAL_IP);
	if (value && strlen (value))
		local_ip = value;
	else {
		g_set_error (error, 0, 0, "connection was incomplete (missing local IP)");
		goto done;
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_NETMASK);
	if (value && strlen (value))
		netmask = value;
	else {
		g_set_error (error, 0, 0, "connection was incomplete (missing netmask)");
		goto done;
	}

	/* Auth type */
	auth_type = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_AUTH_TYPE);
	if (auth_type) {
		if (!strncmp (auth_type, NM_SSH_AUTH_TYPE_PASSWORD, strlen(NM_SSH_AUTH_TYPE_PASSWORD))) {
			password_prompt_nr = 1;
			preferred_authentication = g_strdup("password");
		} else if (!strncmp (auth_type, NM_SSH_AUTH_TYPE_KEY, strlen(NM_SSH_AUTH_TYPE_KEY))) {
			key_file = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_KEY_FILE);
			preferred_authentication = g_strdup("publickey");
		} else { // (!strncmp (auth_type, NM_SSH_AUTH_TYPE_SSH_AGENT, strlen(NM_SSH_AUTH_TYPE_SSH_AGENT))) {
			// Nothing to be done for ssh-agent, the wise choice...
			preferred_authentication = g_strdup("publickey");
		}
	}
	/* Auth type */

	/* Advanced values start */
	value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_PORT);
	if (value && strlen (value))
		port = value;
	else
		port = g_strdup_printf("%d", NM_SSH_DEFAULT_PORT);

	value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_TUNNEL_MTU);
	if (value && strlen (value))
		mtu = value;
	else
		mtu = g_strdup_printf("%d", NM_SSH_DEFAULT_MTU);

	value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_REMOTE_DEV);
	if (value && strlen (value))
		remote_dev = value;
	else
		remote_dev = g_strdup_printf("%d", NM_SSH_DEFAULT_REMOTE_DEV);

	value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_REMOTE_USERNAME);
	if (value && strlen (value))
		remote_username = value;
	else
		remote_username = g_strdup(NM_SSH_DEFAULT_REMOTE_USERNAME);

	value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_SOCKS_ONLY_INTERFACE);
	if (value && strlen (value))
		socks_only_interface = value;
	else
		socks_only_interface = NULL;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_SOCKS_BIND_ADDRESS);
	if (value && strlen (value))
		socks_bind_address = value;
	else
		socks_bind_address = NULL;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_TAP_DEV);
	if (value && IS_YES(value)) {
		device_type = g_strdup("tap");
		tunnel_type = g_strdup("ethernet");
	} else {
		device_type = g_strdup("tun");
		tunnel_type = g_strdup("point-to-point");
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_IP_6);
	if (value && IS_YES(value)) {
		ipv6 = TRUE;

		value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_REMOTE_IP_6);
		if (value && strlen (value))
			remote_ip_6 = value;
		else {
			g_set_error (error, 0, 0, "connection was incomplete (missing IPv6 remote IP)");
			goto done;
		}

		value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_LOCAL_IP_6);
		if (value && strlen (value))
			local_ip_6 = value;
		else {
			g_set_error (error, 0, 0, "connection was incomplete (missing IPv6 local IP)");
			goto done;
		}

		value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_NETMASK_6);
		if (value && strlen (value))
			netmask_6 = value;
		else {
			g_set_error (error, 0, 0, "connection was incomplete (missing IPv6 netmask)");
			goto done;
		}

		ifconfig_cmd_local_6 = g_strdup_printf("%s $DEV_TYPE$LOCAL_DEV add $LOCAL_IP_6/$NETMASK_6", IFCONFIG);
		ifconfig_cmd_remote_6 = g_strdup_printf("%s $DEV_TYPE$REMOTE_DEV add $REMOTE_IP_6/$NETMASK_6", IFCONFIG);
	} else {
		ipv6 = FALSE;
		ifconfig_cmd_local_6 = g_strdup("");
		ifconfig_cmd_remote_6 = g_strdup("");
	}

	/* Advanced values end */

	/* Serialize everything to a file */
	fprintf (f, "#!/bin/bash\n");
	/* Make my life easier and just add the AUTH_TYPE= key, not used though */
	fprintf (f, "%s=%s\n", AUTH_TYPE_KEY, auth_type);
	if (key_file) {
		fprintf (f, "%s=%s\n", KEY_FILE_KEY, key_file);
	}
	fprintf (f, "%s=%s\n", REMOTE_KEY, gateway);
	fprintf (f, "%s=%s\n", REMOTE_USERNAME_KEY, remote_username);
	fprintf (f, "%s=%s\n", REMOTE_IP_KEY, remote_ip);
	fprintf (f, "%s=%s\n", LOCAL_IP_KEY, local_ip);
	fprintf (f, "%s=%s\n", NETMASK_KEY, netmask);
	if (ipv6) {
		fprintf (f, "%s=%s\n", IP_6_KEY, YES);
		fprintf (f, "%s=%s\n", REMOTE_IP_6_KEY, remote_ip_6);
		fprintf (f, "%s=%s\n", LOCAL_IP_6_KEY, local_ip_6);
		fprintf (f, "%s=%s\n", NETMASK_6_KEY, netmask_6);
	}
	fprintf (f, "%s=%s\n", PORT_KEY, port);
	fprintf (f, "%s=%s\n", MTU_KEY, mtu);
	fprintf (f, "%s=%s\n", REMOTE_DEV_KEY, remote_dev);

	/* Assign tun/tap */
	fprintf (f, "%s=%s\n", DEV_TYPE_KEY, device_type);
	fprintf (f, "%s=%s\n", TUNNEL_TYPE_KEY, tunnel_type);

	if (socks_only_interface)
		fprintf (f, "%s=%s\n", SOCKS_ONLY_INTERFACE, socks_only_interface);

	if (socks_bind_address)
		fprintf (f, "%s=%s\n", SOCKS_BIND_ADDRESS, socks_bind_address);

	/* Add a little of bash script to probe for a free tun/tap device */
	if (!socks_only_interface)
	{
		fprintf (f, "for i in `seq 0 255`; do ! %s $DEV_TYPE$i >& /dev/null && LOCAL_DEV=$i && break; done", IFCONFIG);
	}

	fprintf (f, "\n");
	/* The generic lines that will perform the connection */
	fprintf(f, "ssh -f %s -o PreferredAuthentications=%s -o NumberOfPasswordPrompts=%d -o ServerAliveInterval=10 -o TCPKeepAlive=yes -o User=$REMOTE_USERNAME -o Port=$PORT -o HostName=$REMOTE",
		(key_file ? g_strconcat("-i ", key_file, NULL) : ""),
		preferred_authentication,
		password_prompt_nr);

	if (socks_bind_address)
	{
		fprintf(f, " -o DynamicForward=%s", socks_bind_address);
	}

	if (socks_only_interface)
	{
		fprintf(f, " -N $REMOTE");
	}
	else
	{
		fprintf(f, " -o Tunnel=$TUNNEL_TYPE -o TunnelDevice=$LOCAL_DEV:$REMOTE_DEV $REMOTE");
		fprintf(f, " \"%s $DEV_TYPE$REMOTE_DEV $REMOTE_IP netmask $NETMASK pointopoint $LOCAL_IP; %s\" && \\\n", IFCONFIG, ifconfig_cmd_remote_6);
		fprintf(f, "%s $DEV_TYPE$LOCAL_DEV $LOCAL_IP netmask $NETMASK pointopoint $REMOTE_IP; %s\n", IFCONFIG, ifconfig_cmd_local_6);
	}
	fprintf(f, "\\\n");

	success = TRUE;

	g_free(device_type);
	g_free(tunnel_type);
	g_free(ifconfig_cmd_local_6);
	g_free(ifconfig_cmd_remote_6);
	g_free(preferred_authentication);

done:
	fclose (f);
	return success;
}

static char *
get_suggested_filename (NMVpnEditorPlugin *iface, NMConnection *connection)
{
	NMSettingConnection *s_con;
	const char *id;

	g_return_val_if_fail (connection != NULL, NULL);

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_return_val_if_fail (s_con != NULL, NULL);

	id = nm_setting_connection_get_id (s_con);
	g_return_val_if_fail (id != NULL, NULL);

	return g_strdup_printf ("%s (ssh).sh", id);
}

static guint32
get_capabilities (NMVpnEditorPlugin *iface)
{
	return (NM_VPN_EDITOR_PLUGIN_CAPABILITY_IMPORT | NM_VPN_EDITOR_PLUGIN_CAPABILITY_EXPORT | NM_VPN_EDITOR_PLUGIN_CAPABILITY_IPV6);
}

#ifndef NM_VPN_OLD
static NMVpnEditor *
_call_editor_factory (gpointer factory,
                      NMVpnEditorPlugin *editor_plugin,
                      NMConnection *connection,
                      gpointer user_data,
                      GError **error)
{
	return ((NMVpnEditorFactory) factory) (editor_plugin,
	                                       connection,
	                                       error);
}
#endif

static NMVpnEditor *
get_editor (NMVpnEditorPlugin *iface, NMConnection *connection, GError **error)
{
	gpointer gtk3_only_symbol;
	GModule *self_module;
	const char *editor;

	g_return_val_if_fail (SSH_IS_EDITOR_PLUGIN (iface), NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (!error || !*error, NULL);


	self_module = g_module_open (NULL, 0);
	g_module_symbol (self_module, "gtk_container_add", &gtk3_only_symbol);
	g_module_close (self_module);

	if (gtk3_only_symbol) {
		editor = "libnm-gtk3-vpn-plugin-ssh-editor.so";
	} else {
		editor = "libnm-gtk4-vpn-plugin-ssh-editor.so";
	}

#ifdef NM_VPN_OLD
	return nm_ssh_editor_new (connection, error);
#else
	return nm_vpn_plugin_utils_load_editor (editor,
						"nm_vpn_editor_factory_ssh",
						_call_editor_factory,
						iface,
						connection,
						NULL,
						error);
#endif
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case PROP_NAME:
		g_value_set_string (value, SSH_PLUGIN_NAME);
		break;
	case PROP_DESC:
		g_value_set_string (value, SSH_PLUGIN_DESC);
		break;
	case PROP_SERVICE:
		g_value_set_string (value, SSH_PLUGIN_SERVICE);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
ssh_editor_plugin_class_init (SshEditorPluginClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	object_class->get_property = get_property;

	g_object_class_override_property (object_class,
									  PROP_NAME,
									  NM_VPN_EDITOR_PLUGIN_NAME);

	g_object_class_override_property (object_class,
									  PROP_DESC,
									  NM_VPN_EDITOR_PLUGIN_DESCRIPTION);

	g_object_class_override_property (object_class,
									  PROP_SERVICE,
									  NM_VPN_EDITOR_PLUGIN_SERVICE);
}

static void
ssh_editor_plugin_init (SshEditorPlugin *plugin)
{
}

static void
ssh_editor_plugin_interface_init (NMVpnEditorPluginInterface *iface_class)
{
	/* interface implementation */
	iface_class->get_editor = get_editor;
	iface_class->get_capabilities = get_capabilities;
	iface_class->import_from_file = import;
	iface_class->export_to_file = export;
	iface_class->get_suggested_filename = get_suggested_filename;
}

G_MODULE_EXPORT NMVpnEditorPlugin *
nm_vpn_editor_plugin_factory (GError **error)
{
	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	return g_object_new (SSH_TYPE_EDITOR_PLUGIN, NULL);
}
