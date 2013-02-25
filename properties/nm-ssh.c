/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * CVSID: $Id: nm-ssh.c 4232 2008-10-29 09:13:40Z tambeti $
 *
 * nm-ssh.c : GNOME UI dialogs for configuring ssh VPN connections
 *
 * Copyright (C) 2013 Dan Fruehauf, <malkodan@gmail.com>
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <glib/gi18n-lib.h>
#include <string.h>
#include <gtk/gtk.h>

#define NM_VPN_API_SUBJECT_TO_CHANGE

#include <nm-vpn-plugin-ui-interface.h>
#include <nm-setting-vpn.h>
#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>

#include "src/nm-ssh-service.h"
#include "nm-ssh.h"
#include "auth-helpers.h"

#define SSH_PLUGIN_NAME    _("SSH")
#define SSH_PLUGIN_DESC    _("Compatible with the SSH server.")
#define SSH_PLUGIN_SERVICE NM_DBUS_SERVICE_SSH 


/************** plugin class **************/

static void ssh_plugin_ui_interface_init (NMVpnPluginUiInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (SshPluginUi, ssh_plugin_ui, G_TYPE_OBJECT, 0,
						G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_PLUGIN_UI_INTERFACE,
											   ssh_plugin_ui_interface_init))

/************** UI widget class **************/

static void ssh_plugin_ui_widget_interface_init (NMVpnPluginUiWidgetInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (SshPluginUiWidget, ssh_plugin_ui_widget, G_TYPE_OBJECT, 0,
						G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_PLUGIN_UI_WIDGET_INTERFACE,
											   ssh_plugin_ui_widget_interface_init))

#define SSH_PLUGIN_UI_WIDGET_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SSH_TYPE_PLUGIN_UI_WIDGET, SshPluginUiWidgetPrivate))

typedef struct {
	GtkBuilder *builder;
	GtkWidget *widget;
	GtkSizeGroup *group;
	GtkWindowGroup *window_group;
	gboolean window_added;
	GHashTable *advanced;
	gboolean new_connection;
} SshPluginUiWidgetPrivate;


#define COL_AUTH_NAME 0
#define COL_AUTH_PAGE 1
#define COL_AUTH_TYPE 2

GQuark
ssh_plugin_ui_error_quark (void)
{
	static GQuark error_quark = 0;

	if (G_UNLIKELY (error_quark == 0))
		error_quark = g_quark_from_static_string ("ssh-plugin-ui-error-quark");

	return error_quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
ssh_plugin_ui_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Unknown error. */
			ENUM_ENTRY (SSH_PLUGIN_UI_ERROR_UNKNOWN, "UnknownError"),
			/* The connection was missing invalid. */
			ENUM_ENTRY (SSH_PLUGIN_UI_ERROR_INVALID_CONNECTION, "InvalidConnection"),
			/* The specified property was invalid. */
			ENUM_ENTRY (SSH_PLUGIN_UI_ERROR_INVALID_PROPERTY, "InvalidProperty"),
			/* The specified property was missing and is required. */
			ENUM_ENTRY (SSH_PLUGIN_UI_ERROR_MISSING_PROPERTY, "MissingProperty"),
			/* The file to import could not be read. */
			ENUM_ENTRY (SSH_PLUGIN_UI_ERROR_FILE_NOT_READABLE, "FileNotReadable"),
			/* The file to import could was not an SSH client file. */
			ENUM_ENTRY (SSH_PLUGIN_UI_ERROR_FILE_NOT_SSH, "FileNotSSH"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("SshPluginUiError", values);
	}
	return etype;
}

static gboolean
check_validity (SshPluginUiWidget *self, GError **error)
{
	SshPluginUiWidgetPrivate *priv = SSH_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *widget;
	const char *str;

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (!str || !strlen (str)) {
		g_set_error (error,
		             SSH_PLUGIN_UI_ERROR,
		             SSH_PLUGIN_UI_ERROR_INVALID_PROPERTY,
		             NM_SSH_KEY_REMOTE);
		return FALSE;
	}

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "remote_ip_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (!str || !strlen (str)) {
		g_set_error (error,
		             SSH_PLUGIN_UI_ERROR,
		             SSH_PLUGIN_UI_ERROR_INVALID_PROPERTY,
		             NM_SSH_KEY_REMOTE_IP);
		return FALSE;
	}

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "local_ip_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (!str || !strlen (str)) {
		g_set_error (error,
		             SSH_PLUGIN_UI_ERROR,
		             SSH_PLUGIN_UI_ERROR_INVALID_PROPERTY,
		             NM_SSH_KEY_LOCAL_IP);
		return FALSE;
	}

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "netmask_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (!str || !strlen (str)) {
		g_set_error (error,
		             SSH_PLUGIN_UI_ERROR,
		             SSH_PLUGIN_UI_ERROR_INVALID_PROPERTY,
		             NM_SSH_KEY_NETMASK);
		return FALSE;
	}

	return TRUE;
}

static void
stuff_changed_cb (GtkWidget *widget, gpointer user_data)
{
	g_signal_emit_by_name (SSH_PLUGIN_UI_WIDGET (user_data), "changed");
}

static void
advanced_dialog_close_cb (GtkWidget *dialog, gpointer user_data)
{
	gtk_widget_hide (dialog);
	/* gtk_widget_destroy() will remove the window from the window group */
	gtk_widget_destroy (dialog);
}

static void
advanced_dialog_response_cb (GtkWidget *dialog, gint response, gpointer user_data)
{
	SshPluginUiWidget *self = SSH_PLUGIN_UI_WIDGET (user_data);
	SshPluginUiWidgetPrivate *priv = SSH_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GError *error = NULL;

	if (response != GTK_RESPONSE_OK) {
		advanced_dialog_close_cb (dialog, self);
		return;
	}

	if (priv->advanced)
		g_hash_table_destroy (priv->advanced);
	priv->advanced = advanced_dialog_new_hash_from_dialog (dialog, &error);
	if (!priv->advanced) {
		g_message ("%s: error reading advanced settings: %s", __func__, error->message);
		g_error_free (error);
	}
	advanced_dialog_close_cb (dialog, self);

	stuff_changed_cb (NULL, self);
}

static void
advanced_button_clicked_cb (GtkWidget *button, gpointer user_data)
{
	SshPluginUiWidget *self = SSH_PLUGIN_UI_WIDGET (user_data);
	SshPluginUiWidgetPrivate *priv = SSH_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *dialog, *toplevel;

	toplevel = gtk_widget_get_toplevel (priv->widget);
	g_return_if_fail (gtk_widget_is_toplevel (toplevel));

	dialog = advanced_dialog_new (priv->advanced);
	if (!dialog) {
		g_warning ("%s: failed to create the Advanced dialog!", __func__);
		return;
	}

	gtk_window_group_add_window (priv->window_group, GTK_WINDOW (dialog));
	if (!priv->window_added) {
		gtk_window_group_add_window (priv->window_group, GTK_WINDOW (toplevel));
		priv->window_added = TRUE;
	}

	gtk_window_set_transient_for (GTK_WINDOW (dialog), GTK_WINDOW (toplevel));
	g_signal_connect (G_OBJECT (dialog), "response", G_CALLBACK (advanced_dialog_response_cb), self);
	g_signal_connect (G_OBJECT (dialog), "close", G_CALLBACK (advanced_dialog_close_cb), self);

	gtk_widget_show_all (dialog);
}

static void
ipv6_toggled_cb (GtkWidget *check, gpointer user_data)
{
	GtkBuilder *builder = (GtkBuilder *) user_data;
	GtkWidget *widget;

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_ip_6_entry"));
	gtk_widget_set_sensitive (widget, gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (check)));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "local_ip_6_entry"));
	gtk_widget_set_sensitive (widget, gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (check)));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "netmask_6_entry"));
	gtk_widget_set_sensitive (widget, gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (check)));
}

static gboolean
init_plugin_ui (SshPluginUiWidget *self, NMConnection *connection, GError **error)
{
	SshPluginUiWidgetPrivate *priv = SSH_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	NMSettingVPN *s_vpn;
	GtkWidget *widget;
	const char *value;

	s_vpn = nm_connection_get_setting_vpn (connection);

	priv->group = gtk_size_group_new (GTK_SIZE_GROUP_HORIZONTAL);

	/* Remote GW (SSH host) */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, widget);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_REMOTE);
		if (value)
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	/* Remote IP */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "remote_ip_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, widget);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_REMOTE_IP);
		if (value)
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	/* Local IP */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "local_ip_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, widget);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_LOCAL_IP);
		if (value)
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	/* Netmask */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "netmask_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, widget);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_NETMASK);
		if (value)
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	/* Remote IP IPv6 */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "remote_ip_6_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, widget);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_REMOTE_IP_6);
		if (value)
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	/* Local IP IPv6 */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "local_ip_6_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, widget);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_LOCAL_IP_6);
		if (value)
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	/* Netmask IPv6 */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "netmask_6_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, widget);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_NETMASK_6);
		if (value)
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	/* IPv6 options */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "ipv6_checkbutton"));
	g_assert (widget);
	value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_IP_6);
	if (value && !strcmp(value, "yes")) {
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);
	} else {
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), FALSE);
	}
	/* Call the callback to show/hide IPv6 options */
	ipv6_toggled_cb (widget, priv->builder);
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (ipv6_toggled_cb), priv->builder);
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (stuff_changed_cb), self);

	/* If IPV6 is defined, we'll show the whole IPV6 alignment shenanigans */
#if defined(IPV6)
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "ipv6_label"));
	g_assert (widget);
	gtk_widget_show (widget);
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "ipv6_alignment"));
	g_assert (widget);
	gtk_widget_show (widget);
#endif

	/* Advanced button */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "advanced_button"));
	g_signal_connect (G_OBJECT (widget), "clicked", G_CALLBACK (advanced_button_clicked_cb), self);

	return TRUE;
}

static GObject *
get_widget (NMVpnPluginUiWidgetInterface *iface)
{
	SshPluginUiWidget *self = SSH_PLUGIN_UI_WIDGET (iface);
	SshPluginUiWidgetPrivate *priv = SSH_PLUGIN_UI_WIDGET_GET_PRIVATE (self);

	return G_OBJECT (priv->widget);
}

static void
hash_copy_advanced (gpointer key, gpointer data, gpointer user_data)
{
	NMSettingVPN *s_vpn = NM_SETTING_VPN (user_data);
	const char *value = (const char *) data;

	g_return_if_fail (value && strlen (value));

	nm_setting_vpn_add_data_item (s_vpn, (const char *) key, value);
}

static gboolean
update_connection (NMVpnPluginUiWidgetInterface *iface,
                   NMConnection *connection,
                   GError **error)
{
	SshPluginUiWidget *self = SSH_PLUGIN_UI_WIDGET (iface);
	SshPluginUiWidgetPrivate *priv = SSH_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	NMSettingVPN *s_vpn;
	GtkWidget *widget;
	const char *str;
	gboolean valid = FALSE;

	if (!check_validity (self, error))
		return FALSE;

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	g_object_set (s_vpn, NM_SETTING_VPN_SERVICE_TYPE, NM_DBUS_SERVICE_SSH, NULL);

	/* Gateway */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_SSH_KEY_REMOTE, str);

	/* Remote IP */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "remote_ip_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_SSH_KEY_REMOTE_IP, str);

	/* Local IP */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "local_ip_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_SSH_KEY_LOCAL_IP, str);

	/* Netmask */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "netmask_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_SSH_KEY_NETMASK, str);

	/* IPv6 enabled */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "ipv6_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
		nm_setting_vpn_add_data_item (s_vpn, NM_SSH_KEY_IP_6, "yes");

		/* Remote IP IPv6 */
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "remote_ip_6_entry"));
		str = gtk_entry_get_text (GTK_ENTRY (widget));
		if (str && strlen (str))
			nm_setting_vpn_add_data_item (s_vpn, NM_SSH_KEY_REMOTE_IP_6, str);

		/* Local IP IPv6 */
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "local_ip_6_entry"));
		str = gtk_entry_get_text (GTK_ENTRY (widget));
		if (str && strlen (str))
			nm_setting_vpn_add_data_item (s_vpn, NM_SSH_KEY_LOCAL_IP_6, str);

		/* Prefix IPv6 */
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "netmask_6_entry"));
		str = gtk_entry_get_text (GTK_ENTRY (widget));
		if (str && strlen (str))
			nm_setting_vpn_add_data_item (s_vpn, NM_SSH_KEY_NETMASK_6, str);
	}

	if (priv->advanced)
		g_hash_table_foreach (priv->advanced, hash_copy_advanced, s_vpn);

	nm_connection_add_setting (connection, NM_SETTING (s_vpn));
	valid = TRUE;

	return valid;
}

static void
is_new_func (const char *key, const char *value, gpointer user_data)
{
	gboolean *is_new = user_data;

	/* If there are any VPN data items the connection isn't new */
	*is_new = FALSE;
}

static NMVpnPluginUiWidgetInterface *
nm_vpn_plugin_ui_widget_interface_new (NMConnection *connection, GError **error)
{
	NMVpnPluginUiWidgetInterface *object;
	SshPluginUiWidgetPrivate *priv;
	char *ui_file;
	gboolean new = TRUE;
	NMSettingVPN *s_vpn;

	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	object = NM_VPN_PLUGIN_UI_WIDGET_INTERFACE (g_object_new (SSH_TYPE_PLUGIN_UI_WIDGET, NULL));
	if (!object) {
		g_set_error (error, SSH_PLUGIN_UI_ERROR, 0, "could not create ssh object");
		return NULL;
	}

	priv = SSH_PLUGIN_UI_WIDGET_GET_PRIVATE (object);

	ui_file = g_strdup_printf ("%s/%s", UIDIR, "nm-ssh-dialog.ui");
	priv->builder = gtk_builder_new ();

	gtk_builder_set_translation_domain (priv->builder, GETTEXT_PACKAGE);

	if (!gtk_builder_add_from_file (priv->builder, ui_file, error)) {
		g_warning ("Couldn't load builder file: %s",
		           error && *error ? (*error)->message : "(unknown)");
		g_clear_error (error);
		g_set_error (error, SSH_PLUGIN_UI_ERROR, 0,
		             "could not load required resources from %s", ui_file);
		g_free (ui_file);
		g_object_unref (object);
		return NULL;
	}

	g_free (ui_file);

	priv->widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "ssh-vbox"));
	if (!priv->widget) {
		g_set_error (error, SSH_PLUGIN_UI_ERROR, 0, "could not load UI widget");
		g_object_unref (object);
		return NULL;
	}
	g_object_ref_sink (priv->widget);

	priv->window_group = gtk_window_group_new ();

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (s_vpn)
		nm_setting_vpn_foreach_data_item (s_vpn, is_new_func, &new);
	priv->new_connection = new;

	if (!init_plugin_ui (SSH_PLUGIN_UI_WIDGET (object), connection, error)) {
		g_object_unref (object);
		return NULL;
	}

	priv->advanced = advanced_dialog_new_hash_from_connection (connection, error);
	if (!priv->advanced) {
		g_object_unref (object);
		return NULL;
	}

	return object;
}

static void
dispose (GObject *object)
{
	SshPluginUiWidget *plugin = SSH_PLUGIN_UI_WIDGET (object);
	SshPluginUiWidgetPrivate *priv = SSH_PLUGIN_UI_WIDGET_GET_PRIVATE (plugin);

	if (priv->group)
		g_object_unref (priv->group);

	if (priv->window_group)
		g_object_unref (priv->window_group);

	if (priv->widget)
		g_object_unref (priv->widget);

	if (priv->builder)
		g_object_unref (priv->builder);

	if (priv->advanced)
		g_hash_table_destroy (priv->advanced);

	G_OBJECT_CLASS (ssh_plugin_ui_widget_parent_class)->dispose (object);
}

static void
ssh_plugin_ui_widget_class_init (SshPluginUiWidgetClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	g_type_class_add_private (req_class, sizeof (SshPluginUiWidgetPrivate));

	object_class->dispose = dispose;
}

static void
ssh_plugin_ui_widget_init (SshPluginUiWidget *plugin)
{
}

static void
ssh_plugin_ui_widget_interface_init (NMVpnPluginUiWidgetInterface *iface_class)
{
	/* interface implementation */
	iface_class->get_widget = get_widget;
	iface_class->update_connection = update_connection;
}

static gboolean
export (NMVpnPluginUiInterface *iface,
        const char *path,
        NMConnection *connection,
        GError **error)
{
	NMSettingConnection *s_con;
	NMSettingVPN *s_vpn;
	FILE *f;
	const char *value;
	const char *gateway = NULL;
	const char *port = NULL;
	const char *local_ip = NULL;
	const char *remote_ip = NULL;
	const char *netmask = NULL;
	const char *local_ip_6 = NULL;
	const char *remote_ip_6 = NULL;
	const char *netmask_6 = NULL;
	const char *extra_opts = NULL;
	const char *remote_dev = NULL;
	const char *mtu = NULL;
	const char *remote_username = NULL;
	char *device_type = NULL;
	char *tunnel_type = NULL;
	char *ifconfig_cmd_local_6 = NULL;
	char *ifconfig_cmd_remote_6 = NULL;
	gboolean ipv6 = FALSE;
	gboolean success = FALSE;

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_con);

	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);

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

	value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_EXTRA_OPTS);
	if (value && strlen (value))
		extra_opts = value;
	else
		extra_opts = g_strdup(NM_SSH_DEFAULT_EXTRA_OPTS);

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

	value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_TAP_DEV);
	if (value && !strcmp (value, "yes")) {
		device_type = g_strdup("tap");
		tunnel_type = g_strdup("ethernet");
	} else {
		device_type = g_strdup("tun");
		tunnel_type = g_strdup("point-to-point");
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_IP_6);
	if (value && !strcmp (value, "yes")) {
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
	fprintf (f, "REMOTE=%s\n", gateway);
	fprintf (f, "REMOTE_USERNAME=%s\n", remote_username);
	fprintf (f, "REMOTE_IP=%s\n", remote_ip);
	fprintf (f, "LOCAL_IP=%s\n", local_ip);
	fprintf (f, "NETMASK=%s\n", netmask);
	if (ipv6) {
		fprintf (f, "IP_6=%s\n", "yes");
		fprintf (f, "REMOTE_IP_6=%s\n", remote_ip_6);
		fprintf (f, "LOCAL_IP_6=%s\n", local_ip_6);
		fprintf (f, "NETMASK_6=%s\n", netmask_6);
	}
	fprintf (f, "PORT=%s\n", port);
	fprintf (f, "MTU=%s\n", mtu);
	fprintf (f, "EXTRA_OPTS='%s'\n", extra_opts);
	fprintf (f, "REMOTE_DEV=%s\n", remote_dev);

	/* Assign tun/tap */
	fprintf (f, "DEV_TYPE=%s\n", device_type);
	fprintf (f, "TUNNEL_TYPE=%s\n\n", tunnel_type);

	/* Add a little of bash script to probe for a free tun/tap device */
	fprintf (f, "for i in `seq 0 255`; do ! %s $DEV_TYPE$i >& /dev/null && LOCAL_DEV=$i && break; done", IFCONFIG);

	/* The generic lines that will perform the connection */
	fprintf (f, "\n");
	fprintf(f, "ssh -f -v -o Tunnel=$TUNNEL_TYPE -o NumberOfPasswordPrompts=0 $EXTRA_OPTS -w $LOCAL_DEV:$REMOTE_DEV -l $REMOTE_USERNAME -p $PORT $REMOTE \"%s $DEV_TYPE$REMOTE_DEV $REMOTE_IP netmask $NETMASK pointopoint $LOCAL_IP; %s\" && \\\n", IFCONFIG, ifconfig_cmd_remote_6);
	fprintf(f, "%s $DEV_TYPE$LOCAL_DEV $LOCAL_IP netmask $NETMASK pointopoint $REMOTE_IP; %s\n", IFCONFIG, ifconfig_cmd_local_6);

	success = TRUE;

done:
	fclose (f);
	return success;
}

static char *
get_suggested_name (NMVpnPluginUiInterface *iface, NMConnection *connection)
{
	NMSettingConnection *s_con;
	const char *id;

	g_return_val_if_fail (connection != NULL, NULL);

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_return_val_if_fail (s_con != NULL, NULL);

	id = nm_setting_connection_get_id (s_con);
	g_return_val_if_fail (id != NULL, NULL);

	return g_strdup_printf ("%s (ssh).conf", id);
}

static guint32
get_capabilities (NMVpnPluginUiInterface *iface)
{
	// TODO implement import :)
	//return (NM_VPN_PLUGIN_UI_CAPABILITY_IMPORT | NM_VPN_PLUGIN_UI_CAPABILITY_EXPORT);
	return (NM_VPN_PLUGIN_UI_CAPABILITY_EXPORT);
}

static NMVpnPluginUiWidgetInterface *
ui_factory (NMVpnPluginUiInterface *iface, NMConnection *connection, GError **error)
{
	return nm_vpn_plugin_ui_widget_interface_new (connection, error);
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case NM_VPN_PLUGIN_UI_INTERFACE_PROP_NAME:
		g_value_set_string (value, SSH_PLUGIN_NAME);
		break;
	case NM_VPN_PLUGIN_UI_INTERFACE_PROP_DESC:
		g_value_set_string (value, SSH_PLUGIN_DESC);
		break;
	case NM_VPN_PLUGIN_UI_INTERFACE_PROP_SERVICE:
		g_value_set_string (value, SSH_PLUGIN_SERVICE);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
ssh_plugin_ui_class_init (SshPluginUiClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	object_class->get_property = get_property;

	g_object_class_override_property (object_class,
									  NM_VPN_PLUGIN_UI_INTERFACE_PROP_NAME,
									  NM_VPN_PLUGIN_UI_INTERFACE_NAME);

	g_object_class_override_property (object_class,
									  NM_VPN_PLUGIN_UI_INTERFACE_PROP_DESC,
									  NM_VPN_PLUGIN_UI_INTERFACE_DESC);

	g_object_class_override_property (object_class,
									  NM_VPN_PLUGIN_UI_INTERFACE_PROP_SERVICE,
									  NM_VPN_PLUGIN_UI_INTERFACE_SERVICE);
}

static void
ssh_plugin_ui_init (SshPluginUi *plugin)
{
}

static void
ssh_plugin_ui_interface_init (NMVpnPluginUiInterface *iface_class)
{
	/* interface implementation */
	iface_class->ui_factory = ui_factory;
	iface_class->get_capabilities = get_capabilities;
	// TODO implement
	//iface_class->import_from_file = import;
	iface_class->export_to_file = export;
	iface_class->get_suggested_name = get_suggested_name;
}

G_MODULE_EXPORT NMVpnPluginUiInterface *
nm_vpn_plugin_ui_factory (GError **error)
{
	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	return NM_VPN_PLUGIN_UI_INTERFACE (g_object_new (SSH_TYPE_PLUGIN_UI, NULL));
}

