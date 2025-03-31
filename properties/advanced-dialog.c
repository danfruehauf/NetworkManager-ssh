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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <glib/gi18n-lib.h>

#ifdef NM_SSH_OLD
#define NM_VPN_LIBNM_COMPAT
#include <nm-setting-connection.h>
#include <nm-setting-8021x.h>

#else /* !NM_SSH_OLD */

#include <NetworkManager.h>
#endif

#include "advanced-dialog.h"
#include "nm-ssh-editor.h"
#include "nm-service-defines.h"

static const char *advanced_keys[] = {
	NM_SSH_KEY_PORT,
	NM_SSH_KEY_TUNNEL_MTU,
	NM_SSH_KEY_REMOTE_DEV,
	NM_SSH_KEY_TAP_DEV,
	NM_SSH_KEY_REMOTE_USERNAME,
	NM_SSH_KEY_SUDO,
	NM_SSH_KEY_NO_TUNNEL_INTERFACE,
	NM_SSH_KEY_SOCKS_BIND_ADDRESS,
	NM_SSH_KEY_LOCAL_BIND_ADDRESS,
	NM_SSH_KEY_REMOTE_BIND_ADDRESS,
	NULL
};

static void
copy_values (const char *key, const char *value, gpointer user_data)
{
	GHashTable *hash = (GHashTable *) user_data;
	const char **i;

	for (i = &advanced_keys[0]; *i; i++) {
		if (strncmp (key, *i, strlen(key)))
			continue;

		g_hash_table_insert (hash, g_strdup (key), g_strdup (value));
	}
}

GHashTable *
advanced_dialog_new_hash_from_connection (NMConnection *connection,
                                          GError **error)
{
	GHashTable *hash;
	NMSettingVpn *s_vpn;

	hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

	s_vpn = (NMSettingVpn *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);
	nm_setting_vpn_foreach_data_item (s_vpn, copy_values, hash);

	return hash;
}

static void
port_toggled_cb (GtkWidget *check, gpointer user_data)
{
	GtkBuilder *builder = (GtkBuilder *) user_data;
	GtkWidget *widget;

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "port_spinbutton"));
	gtk_widget_set_sensitive (widget, gtk_check_button_get_active (GTK_CHECK_BUTTON (check)));
}

static void
tunmtu_toggled_cb (GtkWidget *check, gpointer user_data)
{
	GtkBuilder *builder = (GtkBuilder *) user_data;
	GtkWidget *widget;

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "tunmtu_spinbutton"));
	gtk_widget_set_sensitive (widget, gtk_check_button_get_active (GTK_CHECK_BUTTON (check)));
}

static void
remote_dev_toggled_cb (GtkWidget *check, gpointer user_data)
{
	GtkBuilder *builder = (GtkBuilder *) user_data;
	GtkWidget *widget;

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_dev_spinbutton"));
	gtk_widget_set_sensitive (widget, gtk_check_button_get_active (GTK_CHECK_BUTTON (check)));
}

static void
remote_username_toggled_cb (GtkWidget *check, gpointer user_data)
{
	GtkBuilder *builder = (GtkBuilder *) user_data;
	GtkWidget *widget;

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "user_warning_revealer"));
	gtk_revealer_set_reveal_child (GTK_REVEALER (widget),
		gtk_check_button_get_active (GTK_CHECK_BUTTON (check)));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_username_entry"));
	gtk_widget_set_sensitive (widget, gtk_check_button_get_active (GTK_CHECK_BUTTON (check)));
}

static void
no_tunnel_interface_toggled_cb (GtkWidget *check, gpointer user_data)
{
	GtkBuilder *builder = (GtkBuilder *) user_data;
	GtkWidget *widget;

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "no_tunnel_interface_entry"));
	gtk_widget_set_sensitive (widget, gtk_check_button_get_active (GTK_CHECK_BUTTON (check)));
}

static void
socks_bind_address_toggled_cb (GtkWidget *check, gpointer user_data)
{
	GtkBuilder *builder = (GtkBuilder *) user_data;
	GtkWidget *widget;

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "socks_bind_address_entry"));
	gtk_widget_set_sensitive (widget, gtk_check_button_get_active (GTK_CHECK_BUTTON (check)));
}

static void
local_bind_address_toggled_cb (GtkWidget *check, gpointer user_data)
{
	GtkBuilder *builder = (GtkBuilder *) user_data;
	GtkWidget *widget;

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "local_bind_address_entry"));
	gtk_widget_set_sensitive (widget, gtk_check_button_get_active (GTK_CHECK_BUTTON (check)));
}

static void
remote_bind_address_toggled_cb (GtkWidget *check, gpointer user_data)
{
	GtkBuilder *builder = (GtkBuilder *) user_data;
	GtkWidget *widget;

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_bind_address_entry"));
	gtk_widget_set_sensitive (widget, gtk_check_button_get_active (GTK_CHECK_BUTTON (check)));
}

GtkWidget *
advanced_dialog_new (GHashTable *hash)
{
	GtkBuilder *builder;
	GtkWidget *dialog = NULL;
	GtkWidget *widget;
	const char *value;
	GError *error = NULL;
	long int tmp;

	g_return_val_if_fail (hash != NULL, NULL);

	builder = gtk_builder_new ();

	gtk_builder_set_translation_domain (builder, GETTEXT_PACKAGE);

	if (!gtk_builder_add_from_resource (builder, "/org/freedesktop/network-manager-ssh/nm-ssh-dialog.ui", &error)) {
		g_warning ("Couldn't load builder file: %s", error->message);
		g_error_free (error);
		g_object_unref (G_OBJECT (builder));
		goto out;
	}

	dialog = GTK_WIDGET (gtk_builder_get_object (builder, "ssh_advanced_dialog"));
	if (!dialog) {
		g_object_unref (G_OBJECT (builder));
		goto out;
	}
	gtk_window_set_modal (GTK_WINDOW (dialog), TRUE);

	g_object_set_data_full (G_OBJECT (dialog), "builder",
	                        builder, (GDestroyNotify) g_object_unref);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "port_checkbutton"));
	g_assert (widget);
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (port_toggled_cb), builder);

	value = g_hash_table_lookup (hash, NM_SSH_KEY_PORT);
	if (value && strlen (value)) {
		errno = 0;
		tmp = strtol (value, NULL, 10);
		if (errno == 0 && tmp > 0 && tmp < 65536) {
			gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), TRUE);

			widget = GTK_WIDGET (gtk_builder_get_object (builder, "port_spinbutton"));
			gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget),
			                           (gdouble) tmp);
		}
		gtk_widget_set_sensitive (widget, TRUE);
	} else {
		gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), FALSE);

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "port_spinbutton"));
		gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget), (gdouble) NM_SSH_DEFAULT_PORT);
		gtk_widget_set_sensitive (widget, FALSE);
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "tunmtu_checkbutton"));
	g_assert (widget);
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (tunmtu_toggled_cb), builder);

	value = g_hash_table_lookup (hash, NM_SSH_KEY_TUNNEL_MTU);
	if (value && strlen (value)) {
		errno = 0;
		tmp = strtol (value, NULL, 10);
		if (errno == 0 && tmp > 0 && tmp < 65536) {
			gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), TRUE);

			widget = GTK_WIDGET (gtk_builder_get_object (builder, "tunmtu_spinbutton"));
			gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget), (gdouble) tmp);
			gtk_widget_set_sensitive (widget, TRUE);
		}
	} else {
		gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), FALSE);

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "tunmtu_spinbutton"));
		gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget), (gdouble) NM_SSH_DEFAULT_MTU);
		gtk_widget_set_sensitive (widget, FALSE);
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_dev_checkbutton"));
	g_assert (widget);
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (remote_dev_toggled_cb), builder);

	value = g_hash_table_lookup (hash, NM_SSH_KEY_REMOTE_DEV);
	if (value && strlen (value)) {
		errno = 0;
		tmp = strtol (value, NULL, 10);
		if (errno == 0 && tmp >= 0 && tmp < 256) {
			gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), TRUE);

			widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_dev_spinbutton"));
			gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget), (gdouble) tmp);
		}
		gtk_widget_set_sensitive (widget, TRUE);
	} else {
		gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), FALSE);

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_dev_spinbutton"));
		gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget), (gdouble) NM_SSH_DEFAULT_REMOTE_DEV);
		gtk_widget_set_sensitive (widget, FALSE);
	}

	value = g_hash_table_lookup (hash, NM_SSH_KEY_TAP_DEV);
	if (value && IS_YES(value)) {
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "tap_checkbutton"));
		gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), TRUE);
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_username_checkbutton"));
	g_assert (widget);
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (remote_username_toggled_cb), builder);

	value = g_hash_table_lookup (hash, NM_SSH_KEY_REMOTE_USERNAME);
	if (value && strlen (value)) {
		gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), TRUE);

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_username_entry"));
		gtk_editable_set_text (GTK_EDITABLE (widget), value);
		gtk_widget_set_sensitive (widget, TRUE);
	} else {
		gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), FALSE);

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_username_entry"));
		gtk_editable_set_text (GTK_EDITABLE (widget), NM_SSH_DEFAULT_REMOTE_USERNAME);
		gtk_widget_set_sensitive (widget, FALSE);
	}

	value = g_hash_table_lookup (hash, NM_SSH_KEY_SUDO);
	if (value && IS_YES(value)) {
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "sudo_checkbutton"));
		gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), TRUE);
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "no_tunnel_interface_checkbutton"));
	g_assert (widget);
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (no_tunnel_interface_toggled_cb), builder);

	value = g_hash_table_lookup (hash, NM_SSH_KEY_NO_TUNNEL_INTERFACE);
	if (value && strlen (value)) {
		gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), TRUE);

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "no_tunnel_interface_entry"));
		gtk_editable_set_text (GTK_EDITABLE (widget), value);
		gtk_widget_set_sensitive (widget, TRUE);
	} else {
		gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), FALSE);

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "no_tunnel_interface_entry"));
		gtk_editable_set_text (GTK_EDITABLE (widget), NM_SSH_DEFAULT_NO_TUNNEL_INTERFACE);
		gtk_widget_set_sensitive (widget, FALSE);
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "socks_bind_address_checkbutton"));
	g_assert (widget);
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (socks_bind_address_toggled_cb), builder);

	value = g_hash_table_lookup (hash, NM_SSH_KEY_SOCKS_BIND_ADDRESS);
	if (value && strlen (value)) {
		gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), TRUE);

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "socks_bind_address_entry"));
		gtk_editable_set_text (GTK_EDITABLE (widget), value);
		gtk_widget_set_sensitive (widget, TRUE);
	} else {
		gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), FALSE);

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "socks_bind_address_entry"));
		gtk_editable_set_text (GTK_EDITABLE (widget), NM_SSH_DEFAULT_SOCKS_BIND_ADDRESS);
		gtk_widget_set_sensitive (widget, FALSE);
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "local_bind_address_checkbutton"));
	g_assert (widget);
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (local_bind_address_toggled_cb), builder);

	value = g_hash_table_lookup (hash, NM_SSH_KEY_LOCAL_BIND_ADDRESS);
	if (value && strlen (value)) {
		gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), TRUE);

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "local_bind_address_entry"));
		gtk_editable_set_text (GTK_EDITABLE (widget), value);
		gtk_widget_set_sensitive (widget, TRUE);
	} else {
		gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), FALSE);

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "local_bind_address_entry"));
		gtk_editable_set_text (GTK_EDITABLE (widget), NM_SSH_DEFAULT_LOCAL_BIND_ADDRESS);
		gtk_widget_set_sensitive (widget, FALSE);
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_bind_address_checkbutton"));
	g_assert (widget);
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (remote_bind_address_toggled_cb), builder);

	value = g_hash_table_lookup (hash, NM_SSH_KEY_REMOTE_BIND_ADDRESS);
	if (value && strlen (value)) {
		gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), TRUE);

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_bind_address_entry"));
		gtk_editable_set_text (GTK_EDITABLE (widget), value);
		gtk_widget_set_sensitive (widget, TRUE);
	} else {
		gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), FALSE);

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_bind_address_entry"));
		gtk_editable_set_text (GTK_EDITABLE (widget), NM_SSH_DEFAULT_REMOTE_BIND_ADDRESS);
		gtk_widget_set_sensitive (widget, FALSE);
	}

out:
	return dialog;
}

GHashTable *
advanced_dialog_new_hash_from_dialog (GtkWidget *dialog, GError **error)
{
	GHashTable  *hash;
	GtkWidget   *widget;
	GtkBuilder  *builder;

	g_return_val_if_fail (dialog != NULL, NULL);
	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	builder = g_object_get_data (G_OBJECT (dialog), "builder");
	g_return_val_if_fail (builder != NULL, NULL);

	hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "tunmtu_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget))) {
		int tunmtu_size;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "tunmtu_spinbutton"));
		tunmtu_size = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));
		g_hash_table_insert (hash, g_strdup (NM_SSH_KEY_TUNNEL_MTU), g_strdup_printf ("%d", tunmtu_size));
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "port_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget))) {
		int port;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "port_spinbutton"));
		port = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));
		g_hash_table_insert (hash, g_strdup (NM_SSH_KEY_PORT), g_strdup_printf ("%d", port));
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_dev_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget))) {
		int remote_dev;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_dev_spinbutton"));
		remote_dev = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));
		g_hash_table_insert (hash, g_strdup (NM_SSH_KEY_REMOTE_DEV), g_strdup_printf ("%d", remote_dev));
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "tap_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget)))
		g_hash_table_insert (hash, g_strdup (NM_SSH_KEY_TAP_DEV), g_strdup (YES));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_username_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget))) {
		const gchar *remote_username;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_username_entry"));
		remote_username = gtk_editable_get_text (GTK_EDITABLE (widget));
		g_hash_table_insert (hash, g_strdup (NM_SSH_KEY_REMOTE_USERNAME), g_strdup(remote_username));
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "sudo_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget)))
		g_hash_table_insert (hash, g_strdup (NM_SSH_KEY_SUDO), g_strdup (YES));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "no_tunnel_interface_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget))) {
		const gchar *no_tunnel_interface;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "no_tunnel_interface_entry"));
		no_tunnel_interface = gtk_editable_get_text (GTK_EDITABLE (widget));
		g_hash_table_insert (hash, g_strdup (NM_SSH_KEY_NO_TUNNEL_INTERFACE), g_strdup(no_tunnel_interface));
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "socks_bind_address_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget))) {
		const gchar *socks_bind_address;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "socks_bind_address_entry"));
		socks_bind_address = gtk_editable_get_text (GTK_EDITABLE (widget));
		g_hash_table_insert (hash, g_strdup (NM_SSH_KEY_SOCKS_BIND_ADDRESS), g_strdup(socks_bind_address));
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "local_bind_address_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget))) {
		const gchar *local_bind_address;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "local_bind_address_entry"));
		local_bind_address = gtk_editable_get_text (GTK_EDITABLE (widget));
		g_hash_table_insert (hash, g_strdup (NM_SSH_KEY_LOCAL_BIND_ADDRESS), g_strdup(local_bind_address));
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_bind_address_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget))) {
		const gchar *remote_bind_address;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_bind_address_entry"));
		remote_bind_address = gtk_editable_get_text (GTK_EDITABLE (widget));
		g_hash_table_insert (hash, g_strdup (NM_SSH_KEY_REMOTE_BIND_ADDRESS), g_strdup(remote_bind_address));
	}

	return hash;
}
