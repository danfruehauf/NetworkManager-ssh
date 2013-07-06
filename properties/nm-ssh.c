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
#include "advanced-dialog.h"

#define SSH_PLUGIN_NAME    _("SSH")
#define SSH_PLUGIN_DESC    _("Compatible with the SSH server.")
#define SSH_PLUGIN_SERVICE NM_DBUS_SERVICE_SSH 

#define PW_TYPE_SAVE   0
#define PW_TYPE_ASK    1
#define PW_TYPE_UNUSED 2

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
		nm_setting_vpn_add_data_item (VPN_CONN, NM_SSH_KEY, "yes"); \
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
show_password_toggled (GtkToggleButton *togglebutton, GtkEntry *password_entry)
{
	gtk_entry_set_visibility (password_entry, gtk_toggle_button_get_active (togglebutton));
}

static void
stuff_changed_cb (GtkWidget *widget, gpointer user_data)
{
	g_signal_emit_by_name (SSH_PLUGIN_UI_WIDGET (user_data), "changed");
}

static void
auth_combo_changed_cb (GtkWidget *combo, gpointer user_data)
{
	SshPluginUiWidget *self = SSH_PLUGIN_UI_WIDGET (user_data);
	SshPluginUiWidgetPrivate *priv = SSH_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *auth_notebook;
	GtkWidget *show_password;
	GtkWidget *file_chooser;
	GtkTreeModel *model;
	GtkTreeIter iter;
	gint new_page = 0;

	auth_notebook = GTK_WIDGET (gtk_builder_get_object (priv->builder, "auth_notebook"));
	g_assert (auth_notebook);
	show_password = GTK_WIDGET (gtk_builder_get_object (priv->builder, "auth_password_show_password_checkbutton"));
	g_assert (show_password);
	file_chooser = GTK_WIDGET (gtk_builder_get_object (priv->builder, "auth_keyfile_filechooserbutton"));
	g_assert (file_chooser);

	model = gtk_combo_box_get_model (GTK_COMBO_BOX (combo));
	g_assert (model);
	g_assert (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (combo), &iter));

	gtk_tree_model_get (model, &iter, COL_AUTH_PAGE, &new_page, -1);

	/* Password entry relevant only to password page (1) */
	gtk_widget_set_sensitive (show_password, new_page == 1);

	/* Key file entry relevant only to key page (2) */
	gtk_widget_set_sensitive (file_chooser, new_page == 2);

	gtk_notebook_set_current_page (GTK_NOTEBOOK (auth_notebook), new_page);

	stuff_changed_cb (combo, self);
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

void
init_auth_widget (GtkBuilder *builder,
                         GtkSizeGroup *group,
                         NMSettingVPN *s_vpn,
                         const char *contype,
                         const char *prefix,
                         ChangedCallback changed_cb,
                         gpointer user_data)
{
	GtkWidget *widget, *widget2;
	g_return_if_fail (builder != NULL);
	g_return_if_fail (group != NULL);
	g_return_if_fail (changed_cb != NULL);
	g_return_if_fail (prefix != NULL);

	/* Three major connection types here: ssh-agent, key file, password */
	if (!strcmp (contype, NM_SSH_AUTH_TYPE_PASSWORD)) {
		const gchar* password;
		NMSettingSecretFlags pw_flags = NM_SETTING_SECRET_FLAG_NONE;
		/* Show password button - by default don't show the password */
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "auth_password_show_password_checkbutton"));
		g_assert (widget);
		widget2 = GTK_WIDGET (gtk_builder_get_object (builder, "auth_password_entry"));
		g_assert (widget2);
		g_signal_connect (widget, "toggled", G_CALLBACK (show_password_toggled), widget2);
		show_password_toggled (GTK_TOGGLE_BUTTON (widget), GTK_ENTRY (widget2));

		/* Load password */
		g_signal_connect (G_OBJECT (widget2), "changed", G_CALLBACK (changed_cb), user_data);
		if (s_vpn) {
			password = nm_setting_vpn_get_secret (s_vpn, NM_SSH_KEY_PASSWORD);
			if (password)
				gtk_entry_set_text (GTK_ENTRY (widget2), password);

			nm_setting_get_secret_flags (NM_SETTING (s_vpn), NM_SSH_KEY_PASSWORD, &pw_flags, NULL);
			/* FIXME */
			//g_object_set_data (G_OBJECT (widget2), "flags", GUINT_TO_POINTER (pw_flags));
		}
	}
	else if (!strcmp (contype, NM_SSH_AUTH_TYPE_KEY)) {
		/* Get key filename and set it */
		const gchar *filename;
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "auth_keyfile_filechooserbutton"));
		/* FIXME add filter */
		//gtk_file_chooser_add_filter (GTK_FILE_CHOOSER (widget), filter);
		gtk_file_chooser_set_local_only (GTK_FILE_CHOOSER (widget), TRUE);
		if (s_vpn) {
			filename = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_KEY_FILE);
			if (filename && strlen (filename))
				gtk_file_chooser_set_filename (GTK_FILE_CHOOSER (widget), filename);
		}
		g_signal_connect (G_OBJECT (widget), "selection-changed", G_CALLBACK (changed_cb), user_data);
	} else if (!strcmp (contype, NM_SSH_AUTH_TYPE_SSH_AGENT)) {
		/* ssh-agent is the default */
		/* Not much to do here! No options for ssh-agent :) */
	} else {
		/* FIXME FATAL ERROR */
	}
}

static void
pw_type_combo_changed_cb (GtkWidget *combo, gpointer user_data)
{
	SshPluginUiWidget *self = SSH_PLUGIN_UI_WIDGET (user_data);
	SshPluginUiWidgetPrivate *priv = SSH_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *entry;

	entry = GTK_WIDGET (gtk_builder_get_object (priv->builder, "auth_password_entry"));
	g_assert (entry);

	/* If the user chose "Not required", desensitize and clear the correct
	 * password entry.
	 */
	switch (gtk_combo_box_get_active (GTK_COMBO_BOX (combo))) {
	case PW_TYPE_ASK:
	case PW_TYPE_UNUSED:
		gtk_entry_set_text (GTK_ENTRY (entry), "");
		gtk_widget_set_sensitive (entry, FALSE);
		break;
	default:
		gtk_widget_set_sensitive (entry, TRUE);
		break;
	}

	stuff_changed_cb (combo, self);
}

static void
init_one_pw_combo (
	SshPluginUiWidget *self,
	NMSettingVPN *s_vpn,
	const char *combo_name,
	const char *secret_key,
	const char *entry_name)
{
	SshPluginUiWidgetPrivate *priv = SSH_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	int active = -1;
	GtkWidget *widget;
	GtkListStore *store;
	GtkTreeIter iter;
	const char *value = NULL;
	guint32 default_idx = 1;
	NMSettingSecretFlags pw_flags = NM_SETTING_SECRET_FLAG_NONE;

	/* If there's already a password and the password type can't be found in
	 * the VPN settings, default to saving it.  Otherwise, always ask for it.
	 */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, entry_name));
	g_assert (widget);
	value = gtk_entry_get_text (GTK_ENTRY (widget));
	if (value && strlen (value))
		default_idx = 0;

	store = gtk_list_store_new (1, G_TYPE_STRING);
	if (s_vpn)
		nm_setting_get_secret_flags (NM_SETTING (s_vpn), secret_key, &pw_flags, NULL);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Saved"), -1);
	if (   (active < 0)
	    && !(pw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED)
	    && !(pw_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)) {
		active = PW_TYPE_SAVE;
	}

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Always Ask"), -1);
	if ((active < 0) && (pw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED))
		active = PW_TYPE_ASK;

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Not Required"), -1);
	if ((active < 0) && (pw_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED))
		active = PW_TYPE_UNUSED;

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, combo_name));
	g_assert (widget);
	gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
	g_object_unref (store);
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active < 0 ? default_idx : active);

	pw_type_combo_changed_cb (widget, self);
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (pw_type_combo_changed_cb), self);
}

/* FIXME break into smaller functions */
static gboolean
init_plugin_ui (SshPluginUiWidget *self, NMConnection *connection, GError **error)
{
	SshPluginUiWidgetPrivate *priv = SSH_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	NMSettingVPN *s_vpn;
	GtkWidget *widget;
	GtkListStore *store;
	GtkTreeIter iter;
	const char *value;
	const char *auth_type = NM_SSH_AUTH_TYPE_SSH_AGENT;
	int active = -1;

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

	/* Authentication combo box */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "auth_auth_type_combobox"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, widget);

	store = gtk_list_store_new (3, G_TYPE_STRING, G_TYPE_INT, G_TYPE_STRING);

	if (s_vpn) {
		auth_type = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_AUTH_TYPE);
		if (auth_type) {
			if (strcmp (auth_type, NM_SSH_AUTH_TYPE_SSH_AGENT)
			    && strcmp (auth_type, NM_SSH_AUTH_TYPE_PASSWORD)
			    && strcmp (auth_type, NM_SSH_AUTH_TYPE_KEY))
				auth_type = NM_SSH_AUTH_TYPE_SSH_AGENT;
		} else
			auth_type = NM_SSH_AUTH_TYPE_SSH_AGENT;
	}

	/* SSH Agent auth widget */
	init_auth_widget (priv->builder, priv->group, s_vpn,
		NM_SSH_KEY_AUTH_TYPE, "ssh-agent",
		stuff_changed_cb, self);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
		COL_AUTH_NAME, _("SSH Agent"),
		COL_AUTH_PAGE, 0,
		COL_AUTH_TYPE, NM_SSH_AUTH_TYPE_SSH_AGENT,
		-1);
	if ((active < 0) && !strcmp (auth_type, NM_SSH_AUTH_TYPE_SSH_AGENT))
		active = 0;

	/* Password auth widget */
	init_auth_widget (priv->builder, priv->group, s_vpn,
		NM_SSH_AUTH_TYPE_PASSWORD, "pw",
		stuff_changed_cb, self);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
		COL_AUTH_NAME, _("Password"),
		COL_AUTH_PAGE, 1,
		COL_AUTH_TYPE, NM_SSH_AUTH_TYPE_PASSWORD,
		-1);
	if ((active < 0) && !strcmp (auth_type, NM_SSH_AUTH_TYPE_PASSWORD))
		active = 1;

	/* Key auth widget */
	init_auth_widget (priv->builder, priv->group, s_vpn,
		NM_SSH_AUTH_TYPE_KEY, "key",
		stuff_changed_cb, self);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
		COL_AUTH_NAME, _("Key Authentication"),
		COL_AUTH_PAGE, 2,
		COL_AUTH_TYPE, NM_SSH_AUTH_TYPE_KEY,
		-1);
	if ((active < 0) && !strcmp (auth_type, NM_SSH_AUTH_TYPE_KEY))
		active = 2;

	gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
	g_object_unref (store);
	g_signal_connect (widget, "changed", G_CALLBACK (auth_combo_changed_cb), self);
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active < 0 ? 0 : active);

	/* Combo box for save/don't save password */
	init_one_pw_combo (
		self,
		s_vpn,
		"auth_password_save_password_combobox",
		NM_SSH_KEY_PASSWORD,
		"auth_password_entry");


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

static gboolean auth_widget_update_connection (
	GtkBuilder *builder,
	NMSettingVPN *s_vpn)
{
	/* This function populates s_vpn with the auth properties */
	GtkWidget *widget;
	GtkComboBox *combo;
	GtkTreeModel *model;
	GtkTreeIter iter;
	char *auth_type = NULL;
	gboolean success = TRUE;

	combo = GTK_COMBO_BOX (GTK_WIDGET (gtk_builder_get_object (builder, "auth_auth_type_combobox")));
	model = gtk_combo_box_get_model (combo);

	success = gtk_combo_box_get_active_iter (combo, &iter);
	g_return_val_if_fail (success == TRUE, FALSE);
	gtk_tree_model_get (model, &iter, COL_AUTH_TYPE, &auth_type, -1);

	/* Set auth type */
	nm_setting_vpn_add_data_item (s_vpn, NM_SSH_KEY_AUTH_TYPE, auth_type);

	if (!strcmp (auth_type, NM_SSH_AUTH_TYPE_PASSWORD)) {
		/* Password auth */
		const gchar *password;
		NMSettingSecretFlags pw_flags = NM_SETTING_SECRET_FLAG_NONE;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "auth_password_entry"));
		password = gtk_entry_get_text (GTK_ENTRY (widget));
		/* Store password */
		if (password && strlen (password)) {
			nm_setting_vpn_add_secret (s_vpn, NM_SSH_KEY_PASSWORD, password);
			nm_setting_set_secret_flags (NM_SETTING (s_vpn), NM_SSH_KEY_PASSWORD, pw_flags, NULL);
		}
	}
	else if (!strcmp (auth_type, NM_SSH_AUTH_TYPE_KEY)) {
		/* Key auth */
		gchar *filename;
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "auth_keyfile_filechooserbutton"));
		filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
		if (filename && strlen (filename)) {
			nm_setting_vpn_add_data_item (s_vpn, NM_SSH_KEY_KEY_FILE, filename);
		}
		g_free (filename);
	}
	else if (!strcmp (auth_type, NM_SSH_AUTH_TYPE_SSH_AGENT)) {
		/* SSH AGENT auth */
		/* Nothing to set here, honestly!! It's here just for the sake of order */
	}
	else {
		success = FALSE;
	}

	g_free (auth_type);

	return success;
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

	/* Authentication type */
	valid &= auth_widget_update_connection (priv->builder, s_vpn);

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

	priv->widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "ssh_main_vbox"));
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

static NMConnection *
import (NMVpnPluginUiInterface *iface, const char *path, GError **error)
{
	NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingVPN *s_vpn;
	char *contents = NULL;
	char **lines = NULL;
	char *ext;
	char **line;

	ext = strrchr (path, '.');
	if (!ext) {
		g_set_error (error,
		             SSH_PLUGIN_UI_ERROR,
		             SSH_PLUGIN_UI_ERROR_FILE_NOT_SSH,
		             "unknown OpenVPN file extension, should be .sh");
		goto out;
	}

	if (strcmp (ext, ".sh")) {
		g_set_error (error,
		             SSH_PLUGIN_UI_ERROR,
		             SSH_PLUGIN_UI_ERROR_FILE_NOT_SSH,
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
		             SSH_PLUGIN_UI_ERROR,
		             SSH_PLUGIN_UI_ERROR_FILE_NOT_READABLE,
		             "not a valid OpenVPN configuration file");
		goto out;
	}

	connection = nm_connection_new ();
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
		PARSE_IMPORT_KEY_BOOL (NO_DEFAULT_ROUTE_KEY, NM_SSH_KEY_NO_DEFAULT_ROUTE, items, s_vpn, "yes")

		/* Some extra care required with extra_opts as we need to:
		 * 1. Use the whole line (might contain = chars in it)
		 * 2. Strip the single/double quotes */
		if (!strncmp (items[0], EXTRA_OPTS_KEY, strlen (items[0]))) {
			gchar *parsed_extra_opts = NULL;
			gchar *unquoted_extra_opts = NULL;
			/* Read the whole line, witout the EXTRA_OPTS= part */
			parsed_extra_opts = g_strdup(*line + strlen(EXTRA_OPTS_KEY) + 1);

			/* Check if string is quoted */
			if ( (parsed_extra_opts[0] == '"' && parsed_extra_opts[strlen(parsed_extra_opts)-1] == '"') ||
				/* String is quoted (would usually be), lets strip the quotes */
				(parsed_extra_opts[0] == '\'' && parsed_extra_opts[strlen(parsed_extra_opts)-1] == '\'') ) {
				/* Unquote string */
				parsed_extra_opts[strlen(parsed_extra_opts)-1] = '\0';
				unquoted_extra_opts = parsed_extra_opts + 1;
			}
			/* After all this effort, try to compare to the default value */
			if (strncmp(unquoted_extra_opts, NM_SSH_DEFAULT_EXTRA_OPTS, strlen(unquoted_extra_opts)))
				nm_setting_vpn_add_data_item (s_vpn, NM_SSH_KEY_EXTRA_OPTS, unquoted_extra_opts);
			g_free (items);
			g_free (parsed_extra_opts);
			continue;
		}
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
export (NMVpnPluginUiInterface *iface,
        const char *path,
        NMConnection *connection,
        GError **error)
{
	NMSettingConnection *s_con;
	NMSettingVPN *s_vpn;
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
	const char *extra_opts = NULL;
	const char *remote_dev = NULL;
	const char *mtu = NULL;
	const char *remote_username = NULL;
	char *device_type = NULL;
	char *tunnel_type = NULL;
	char *ifconfig_cmd_local_6 = NULL;
	char *ifconfig_cmd_remote_6 = NULL;
	char *preferred_authentication = NULL;
	unsigned password_prompt_nr = 0;
	gboolean ipv6 = FALSE;
	gboolean no_default_route = FALSE;
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

	/* Auth type */
	auth_type = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_AUTH_TYPE);
	if (auth_type) {
		if (!strcmp (auth_type, NM_SSH_AUTH_TYPE_PASSWORD)) {
			password_prompt_nr = 1;
			preferred_authentication = g_strdup("password");
		} else if (!strcmp (auth_type, NM_SSH_AUTH_TYPE_KEY)) {
			key_file = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_KEY_FILE);
			preferred_authentication = g_strdup("publickey");
		} else { // (!strcmp (auth_type, NM_SSH_AUTH_TYPE_SSH_AGENT)) {
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

	value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_NO_DEFAULT_ROUTE);
	if (value && !strcmp (value, "yes")) {
		no_default_route = TRUE;
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
		fprintf (f, "%s=%s\n", IP_6_KEY, "yes");
		fprintf (f, "%s=%s\n", REMOTE_IP_6_KEY, remote_ip_6);
		fprintf (f, "%s=%s\n", LOCAL_IP_6_KEY, local_ip_6);
		fprintf (f, "%s=%s\n", NETMASK_6_KEY, netmask_6);
	}
	fprintf (f, "%s=%s\n", PORT_KEY, port);
	fprintf (f, "%s=%s\n", MTU_KEY, mtu);
	fprintf (f, "%s='%s'\n", EXTRA_OPTS_KEY, extra_opts);
	fprintf (f, "%s=%s\n", REMOTE_DEV_KEY, remote_dev);

	/* Assign tun/tap */
	fprintf (f, "%s=%s\n", DEV_TYPE_KEY, device_type);
	fprintf (f, "%s=%s\n", TUNNEL_TYPE_KEY, tunnel_type);
	fprintf (f, "%s=%s\n\n", NO_DEFAULT_ROUTE_KEY,
		no_default_route == TRUE ? "yes" : "no");

	/* Add a little of bash script to probe for a free tun/tap device */
	fprintf (f, "for i in `seq 0 255`; do ! %s $DEV_TYPE$i >& /dev/null && LOCAL_DEV=$i && break; done", IFCONFIG);

	/* The generic lines that will perform the connection */
	fprintf (f, "\n");
	fprintf(f, "ssh -f %s -o PreferredAuthentications=%s -o NumberOfPasswordPrompts=%d -o Tunnel=$TUNNEL_TYPE $EXTRA_OPTS -o TunnelDevice=$LOCAL_DEV:$REMOTE_DEV -o User=$REMOTE_USERNAME -o Port=$PORT -o HostName=$REMOTE $REMOTE \"%s $DEV_TYPE$REMOTE_DEV $REMOTE_IP netmask $NETMASK pointopoint $LOCAL_IP; %s\" && \\\n",
		(key_file ? g_strconcat("-i ", key_file, NULL) : ""),
		preferred_authentication,
		password_prompt_nr,
		IFCONFIG,
		ifconfig_cmd_remote_6);
	fprintf(f, "%s $DEV_TYPE$LOCAL_DEV $LOCAL_IP netmask $NETMASK pointopoint $REMOTE_IP; %s\n", IFCONFIG, ifconfig_cmd_local_6);

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
get_suggested_name (NMVpnPluginUiInterface *iface, NMConnection *connection)
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
get_capabilities (NMVpnPluginUiInterface *iface)
{
	return (NM_VPN_PLUGIN_UI_CAPABILITY_IMPORT | NM_VPN_PLUGIN_UI_CAPABILITY_EXPORT);
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
	iface_class->import_from_file = import;
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

