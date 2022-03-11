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

#include <gtk/gtk.h>

#include "nm-ssh-editor.h"
#include "advanced-dialog.h"

#define PW_TYPE_SAVE   0
#define PW_TYPE_ASK    1

static void ssh_editor_interface_init (NMVpnEditorInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (SshEditor, ssh_editor, G_TYPE_OBJECT, 0,
						G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_EDITOR,
											   ssh_editor_interface_init))

#define SSH_EDITOR_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SSH_TYPE_EDITOR, SshEditorPrivate))

typedef struct {
	GtkBuilder *builder;
	GtkWidget *widget;
	GtkSizeGroup *group;
	GtkWindowGroup *window_group;
	gboolean window_added;
	GHashTable *advanced;
	gboolean new_connection;
} SshEditorPrivate;


#define COL_AUTH_NAME 0
#define COL_AUTH_PAGE 1
#define COL_AUTH_TYPE 2

static gboolean
check_validity (SshEditor *self, GError **error)
{
	SshEditorPrivate *priv = SSH_EDITOR_GET_PRIVATE (self);
	GtkWidget *widget;
	const char *str;

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (!str || !strlen (str)) {
		g_set_error (error,
		             NMV_EDITOR_PLUGIN_ERROR,
		             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
		             NM_SSH_KEY_REMOTE);
		return FALSE;
	}

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "remote_ip_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (!str || !strlen (str)) {
		g_set_error (error,
		             NMV_EDITOR_PLUGIN_ERROR,
		             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
		             NM_SSH_KEY_REMOTE_IP);
		return FALSE;
	}

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "local_ip_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (!str || !strlen (str)) {
		g_set_error (error,
		             NMV_EDITOR_PLUGIN_ERROR,
		             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
		             NM_SSH_KEY_LOCAL_IP);
		return FALSE;
	}

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "netmask_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (!str || !strlen (str)) {
		g_set_error (error,
		             NMV_EDITOR_PLUGIN_ERROR,
		             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
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
	g_signal_emit_by_name (SSH_EDITOR (user_data), "changed");
}

static void
auth_combo_changed_cb (GtkWidget *combo, gpointer user_data)
{
	SshEditor *self = SSH_EDITOR (user_data);
	SshEditorPrivate *priv = SSH_EDITOR_GET_PRIVATE (self);
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
	SshEditor *self = SSH_EDITOR (user_data);
	SshEditorPrivate *priv = SSH_EDITOR_GET_PRIVATE (self);
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
	SshEditor *self = SSH_EDITOR (user_data);
	SshEditorPrivate *priv = SSH_EDITOR_GET_PRIVATE (self);
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
                         NMSettingVpn *s_vpn,
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
	if (!strncmp (contype, NM_SSH_AUTH_TYPE_PASSWORD, strlen(NM_SSH_AUTH_TYPE_PASSWORD))) {
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
	else if (!strncmp (contype, NM_SSH_AUTH_TYPE_KEY, strlen(NM_SSH_AUTH_TYPE_KEY))) {
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
	} else if (!strncmp (contype, NM_SSH_AUTH_TYPE_SSH_AGENT, strlen(NM_SSH_AUTH_TYPE_SSH_AGENT))) {
		/* ssh-agent is the default */
		/* Not much to do here! No options for ssh-agent :) */
	} else {
		/* FIXME FATAL ERROR */
	}
}

static void
pw_type_combo_changed_cb (GtkWidget *combo, gpointer user_data)
{
	SshEditor *self = SSH_EDITOR (user_data);
	SshEditorPrivate *priv = SSH_EDITOR_GET_PRIVATE (self);
	GtkWidget *entry;

	entry = GTK_WIDGET (gtk_builder_get_object (priv->builder, "auth_password_entry"));
	g_assert (entry);

	/* If the user chose "Not required", desensitize and clear the correct
	 * password entry.
	 */
	switch (gtk_combo_box_get_active (GTK_COMBO_BOX (combo))) {
	case PW_TYPE_ASK:
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
	SshEditor *self,
	NMSettingVpn *s_vpn,
	const char *combo_name,
	const char *secret_key,
	const char *entry_name)
{
	SshEditorPrivate *priv = SSH_EDITOR_GET_PRIVATE (self);
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
	    && !(pw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED)) {
		active = PW_TYPE_SAVE;
	}

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Always Ask"), -1);
	if ((active < 0) && (pw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED))
		active = PW_TYPE_ASK;

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
init_editor_plugin (SshEditor *self, NMConnection *connection, GError **error)
{
	SshEditorPrivate *priv = SSH_EDITOR_GET_PRIVATE (self);
	NMSettingVpn *s_vpn;
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
	if (value && IS_YES(value)) {
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);
	} else {
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), FALSE);
	}
	/* Call the callback to show/hide IPv6 options */
	ipv6_toggled_cb (widget, priv->builder);
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (ipv6_toggled_cb), priv->builder);
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (stuff_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "ipv6_label"));
	g_assert (widget);
	gtk_widget_show (widget);
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "ipv6_alignment"));
	g_assert (widget);
	gtk_widget_show (widget);

	/* Authentication combo box */
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "auth_auth_type_combobox"));
	g_return_val_if_fail (widget != NULL, FALSE);
	gtk_size_group_add_widget (priv->group, widget);

	store = gtk_list_store_new (3, G_TYPE_STRING, G_TYPE_INT, G_TYPE_STRING);

	if (s_vpn) {
		auth_type = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_AUTH_TYPE);
		if (auth_type) {
			if (strncmp (auth_type, NM_SSH_AUTH_TYPE_SSH_AGENT, strlen(NM_SSH_AUTH_TYPE_SSH_AGENT))
			    && strncmp (auth_type, NM_SSH_AUTH_TYPE_PASSWORD, strlen(NM_SSH_AUTH_TYPE_PASSWORD))
			    && strncmp (auth_type, NM_SSH_AUTH_TYPE_KEY, strlen(NM_SSH_AUTH_TYPE_KEY)))
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
	if ((active < 0) && !strncmp (auth_type, NM_SSH_AUTH_TYPE_SSH_AGENT, strlen(NM_SSH_AUTH_TYPE_SSH_AGENT)))
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
	if ((active < 0) && !strncmp (auth_type, NM_SSH_AUTH_TYPE_PASSWORD, strlen(NM_SSH_AUTH_TYPE_PASSWORD)))
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
	if ((active < 0) && !strncmp (auth_type, NM_SSH_AUTH_TYPE_KEY, strlen(NM_SSH_AUTH_TYPE_KEY)))
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
get_widget (NMVpnEditor *iface)
{
	SshEditor *self = SSH_EDITOR (iface);
	SshEditorPrivate *priv = SSH_EDITOR_GET_PRIVATE (self);

	return G_OBJECT (priv->widget);
}

static void
hash_copy_advanced (gpointer key, gpointer data, gpointer user_data)
{
	NMSettingVpn *s_vpn = NM_SETTING_VPN (user_data);
	const char *value = (const char *) data;

	g_return_if_fail (value && strlen (value));

	nm_setting_vpn_add_data_item (s_vpn, (const char *) key, value);
}

static gboolean auth_widget_update_connection (
	GtkBuilder *builder,
	NMSettingVpn *s_vpn)
{
	/* This function populates s_vpn with the auth properties */
	GtkWidget *widget;
	GtkWidget *combo_password;
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

	if (!strncmp (auth_type, NM_SSH_AUTH_TYPE_PASSWORD, strlen(NM_SSH_AUTH_TYPE_PASSWORD))) {
		/* Password auth */
		const gchar *password;
		NMSettingSecretFlags pw_flags = NM_SETTING_SECRET_FLAG_NONE;

		/* Grab original password flags */
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "auth_password_entry"));
		pw_flags = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (widget), "flags"));
		combo_password = GTK_WIDGET (gtk_builder_get_object (builder, "auth_password_save_password_combobox"));

		/* And set new ones based on the type combo */
		switch (gtk_combo_box_get_active (GTK_COMBO_BOX (combo_password))) {
		case PW_TYPE_SAVE:
			password = gtk_entry_get_text (GTK_ENTRY (widget));
			if (password && strlen (password))
				nm_setting_vpn_add_secret (s_vpn, NM_SSH_KEY_PASSWORD, password);
			break;
		case PW_TYPE_ASK:
		default:
			pw_flags |= NM_SETTING_SECRET_FLAG_NOT_SAVED;
			break;
		}

		/* Set new secret flags */
		nm_setting_set_secret_flags (NM_SETTING (s_vpn), NM_SSH_KEY_PASSWORD, pw_flags, NULL);
	}
	else if (!strncmp (auth_type, NM_SSH_AUTH_TYPE_KEY, strlen(NM_SSH_AUTH_TYPE_KEY))) {
		/* Key auth */
		gchar *filename;
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "auth_keyfile_filechooserbutton"));
		filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
		if (filename && strlen (filename)) {
			nm_setting_vpn_add_data_item (s_vpn, NM_SSH_KEY_KEY_FILE, filename);
		}
		g_free (filename);
	}
	else if (!strncmp (auth_type, NM_SSH_AUTH_TYPE_SSH_AGENT, strlen(NM_SSH_AUTH_TYPE_SSH_AGENT))) {
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
update_connection (NMVpnEditor *iface,
                   NMConnection *connection,
                   GError **error)
{
	SshEditor *self = SSH_EDITOR (iface);
	SshEditorPrivate *priv = SSH_EDITOR_GET_PRIVATE (self);
	NMSettingVpn *s_vpn;
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
		nm_setting_vpn_add_data_item (s_vpn, NM_SSH_KEY_IP_6, YES);

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

NMVpnEditor *
nm_ssh_editor_new (NMConnection *connection, GError **error)
{
	NMVpnEditor *object;
	SshEditorPrivate *priv;
	gboolean new = TRUE;
	NMSettingVpn *s_vpn;

	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	object = g_object_new (SSH_TYPE_EDITOR, NULL);
	if (!object) {
		g_set_error (error, NMV_EDITOR_PLUGIN_ERROR, 0, "could not create ssh object");
		return NULL;
	}

	priv = SSH_EDITOR_GET_PRIVATE (object);

	priv->builder = gtk_builder_new ();

	gtk_builder_set_translation_domain (priv->builder, GETTEXT_PACKAGE);

	if (!gtk_builder_add_from_resource (priv->builder, "/org/freedesktop/network-manager-ssh/nm-ssh-dialog.ui", error)) {
		g_warning ("Couldn't load builder file: %s",
		           error && *error ? (*error)->message : "(unknown)");
		g_object_unref (object);
		return NULL;
	}

	priv->widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "ssh_main_vbox"));
	if (!priv->widget) {
		g_set_error (error, NMV_EDITOR_PLUGIN_ERROR, 0, "could not load UI widget");
		g_object_unref (object);
		return NULL;
	}
	g_object_ref_sink (priv->widget);

	priv->window_group = gtk_window_group_new ();

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (s_vpn)
		nm_setting_vpn_foreach_data_item (s_vpn, is_new_func, &new);
	priv->new_connection = new;

	if (!init_editor_plugin (SSH_EDITOR (object), connection, error)) {
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
	SshEditor *plugin = SSH_EDITOR (object);
	SshEditorPrivate *priv = SSH_EDITOR_GET_PRIVATE (plugin);

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

	G_OBJECT_CLASS (ssh_editor_parent_class)->dispose (object);
}

static void
ssh_editor_class_init (SshEditorClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	g_type_class_add_private (req_class, sizeof (SshEditorPrivate));

	object_class->dispose = dispose;
}

static void
ssh_editor_init (SshEditor *plugin)
{
}

static void
ssh_editor_interface_init (NMVpnEditorInterface *iface_class)
{
	/* interface implementation */
	iface_class->get_widget = get_widget;
	iface_class->update_connection = update_connection;
}

/*****************************************************************************/

#ifndef NM_VPN_OLD

#include "nm-ssh-editor-plugin.h"

G_MODULE_EXPORT NMVpnEditor *
nm_vpn_editor_factory_ssh (NMVpnEditorPlugin *editor_plugin,
                           NMConnection *connection,
                           GError **error)
{
	g_return_val_if_fail (!error || !*error, NULL);

	return nm_ssh_editor_new (connection, error);
}
#endif
