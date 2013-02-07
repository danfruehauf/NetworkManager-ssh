/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
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

#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <glib/gi18n-lib.h>
#include <nm-setting-connection.h>
#include <nm-setting-8021x.h>

#include "auth-helpers.h"
#include "nm-ssh.h"
#include "src/nm-ssh-service.h"
#include "common/utils.h"

#define PW_TYPE_SAVE   0
#define PW_TYPE_ASK    1
#define PW_TYPE_UNUSED 2

static void
show_password (GtkToggleButton *togglebutton, GtkEntry *password_entry)
{
	gtk_entry_set_visibility (password_entry, gtk_toggle_button_get_active (togglebutton));
}

static GtkWidget *
setup_secret_widget (GtkBuilder *builder,
                     const char *widget_name,
                     NMSettingVPN *s_vpn,
                     const char *secret_key)
{
	NMSettingSecretFlags pw_flags = NM_SETTING_SECRET_FLAG_NONE;
	GtkWidget *widget;
	GtkWidget *show_passwords;
	const char *tmp;

	widget = GTK_WIDGET (gtk_builder_get_object (builder, widget_name));
	g_assert (widget);

	show_passwords = GTK_WIDGET (gtk_builder_get_object (builder, "show_passwords"));
	g_signal_connect (show_passwords, "toggled", G_CALLBACK (show_password), widget);

	if (s_vpn) {
		tmp = nm_setting_vpn_get_secret (s_vpn, secret_key);
		if (tmp)
			gtk_entry_set_text (GTK_ENTRY (widget), tmp);

		nm_setting_get_secret_flags (NM_SETTING (s_vpn), secret_key, &pw_flags, NULL);
		g_object_set_data (G_OBJECT (widget), "flags", GUINT_TO_POINTER (pw_flags));
	}

	return widget;
}

static void
tls_cert_changed_cb (GtkWidget *widget, GtkWidget *next_widget)
{
	GtkFileChooser *this, *next;
	char *fname, *next_fname;

	/* If the just-changed file chooser is a PKCS#12 file, then all of the
	 * TLS filechoosers have to be PKCS#12.  But if it just changed to something
	 * other than a PKCS#12 file, then clear out the other file choosers.
	 *
	 * Basically, all the choosers have to contain PKCS#12 files, or none of
	 * them can, because PKCS#12 files contain everything required for the TLS
	 * connection (CA, client cert, private key).
	 */

	this = GTK_FILE_CHOOSER (widget);
	next = GTK_FILE_CHOOSER (next_widget);

	fname = gtk_file_chooser_get_filename (this);
	if (is_pkcs12 (fname)) {
		/* Make sure all choosers have this PKCS#12 file */
		next_fname = gtk_file_chooser_get_filename (next);
		if (!next_fname || strcmp (fname, next_fname)) {
			/* Next chooser was different, make it the same as the first */
			gtk_file_chooser_set_filename (next, fname);
		}
		g_free (fname);
		g_free (next_fname);
		return;
	}
	g_free (fname);

	/* Just-chosen file isn't PKCS#12 or no file was chosen, so clear out other
	 * file selectors that have PKCS#12 files in them.
	 */
	next_fname = gtk_file_chooser_get_filename (next);
	if (is_pkcs12 (next_fname))
		gtk_file_chooser_set_filename (next, NULL);
	g_free (next_fname);
}

static void
pw_type_combo_changed_cb (GtkWidget *combo, gpointer user_data)
{
	GtkWidget *entry = user_data;

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
}

static void
init_one_pw_combo (GtkBuilder *builder,
                   NMSettingVPN *s_vpn,
                   const char *prefix,
                   const char *secret_key,
                   GtkWidget *entry_widget,
                   ChangedCallback changed_cb,
                   gpointer user_data)
{
	int active = -1;
	GtkWidget *widget;
	GtkListStore *store;
	GtkTreeIter iter;
	const char *value = NULL;
	char *tmp;
	guint32 default_idx = 1;
	NMSettingSecretFlags pw_flags = NM_SETTING_SECRET_FLAG_NONE;

	/* If there's already a password and the password type can't be found in
	 * the VPN settings, default to saving it.  Otherwise, always ask for it.
	 */
	value = gtk_entry_get_text (GTK_ENTRY (entry_widget));
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

	tmp = g_strdup_printf ("%s_pass_type_combo", prefix);
	widget = GTK_WIDGET (gtk_builder_get_object (builder, tmp));
	g_assert (widget);
	g_free (tmp);

	gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
	g_object_unref (store);
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active < 0 ? default_idx : active);
	pw_type_combo_changed_cb (widget, entry_widget);

	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (pw_type_combo_changed_cb), entry_widget);
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (changed_cb), user_data);
}

static const char *
find_tag (const char *tag, const char *buf, gsize len)
{
	gsize i, taglen;

	taglen = strlen (tag);
	if (len < taglen)
		return NULL;

	for (i = 0; i < len - taglen + 1; i++) {
		if (memcmp (buf + i, tag, taglen) == 0)
			return buf + i;
	}
	return NULL;
}

static const char *advanced_keys[] = {
	NM_SSH_KEY_PORT,
	NM_SSH_KEY_TUNNEL_MTU,
	NM_SSH_KEY_EXTRA_OPTS,
	NM_SSH_KEY_REMOTE_TUN,
	NULL
};

static void
copy_values (const char *key, const char *value, gpointer user_data)
{
	GHashTable *hash = (GHashTable *) user_data;
	const char **i;

	for (i = &advanced_keys[0]; *i; i++) {
		if (strcmp (key, *i))
			continue;

		g_hash_table_insert (hash, g_strdup (key), g_strdup (value));
	}
}

GHashTable *
advanced_dialog_new_hash_from_connection (NMConnection *connection,
                                          GError **error)
{
	GHashTable *hash;
	NMSettingVPN *s_vpn;

	hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);
	nm_setting_vpn_foreach_data_item (s_vpn, copy_values, hash);

	return hash;
}

static void
port_toggled_cb (GtkWidget *check, gpointer user_data)
{
	GtkBuilder *builder = (GtkBuilder *) user_data;
	GtkWidget *widget;

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "port_spinbutton"));
	gtk_widget_set_sensitive (widget, gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (check)));
}

static void
tunmtu_toggled_cb (GtkWidget *check, gpointer user_data)
{
	GtkBuilder *builder = (GtkBuilder *) user_data;
	GtkWidget *widget;

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "tunmtu_spinbutton"));
	gtk_widget_set_sensitive (widget, gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (check)));
}

static void
extra_opts_toggled_cb (GtkWidget *check, gpointer user_data)
{
	GtkBuilder *builder = (GtkBuilder *) user_data;
	GtkWidget *widget;

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "extra_opts_entry"));
	gtk_widget_set_sensitive (widget, gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (check)));
}

static void
remote_tun_toggled_cb (GtkWidget *check, gpointer user_data)
{
	GtkBuilder *builder = (GtkBuilder *) user_data;
	GtkWidget *widget;

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_tun_spinbutton"));
	gtk_widget_set_sensitive (widget, gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (check)));
}

static const char *
nm_find_ssh (void)
{
	static const char *ssh_binary_paths[] = {
		"/usr/sbin/ssh",
		"/sbin/ssh",
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

GtkWidget *
advanced_dialog_new (GHashTable *hash)
{
	GtkBuilder *builder;
	GtkWidget *dialog = NULL;
	char *ui_file = NULL;
	GtkWidget *widget;
	const char *value;
	GError *error = NULL;
	long int tmp;

	g_return_val_if_fail (hash != NULL, NULL);

	ui_file = g_strdup_printf ("%s/%s", UIDIR, "nm-ssh-dialog.ui");
	builder = gtk_builder_new ();

	gtk_builder_set_translation_domain (builder, GETTEXT_PACKAGE);

	if (!gtk_builder_add_from_file (builder, ui_file, &error)) {
		g_warning ("Couldn't load builder file: %s", error->message);
		g_error_free (error);
		g_object_unref (G_OBJECT (builder));
		goto out;
	}

	dialog = GTK_WIDGET (gtk_builder_get_object (builder, "ssh-advanced-dialog"));
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
			gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);

			widget = GTK_WIDGET (gtk_builder_get_object (builder, "port_spinbutton"));
			gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget),
			                           (gdouble) tmp);
		}
		gtk_widget_set_sensitive (widget, TRUE);
	} else {
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), FALSE);

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "port_spinbutton"));
		gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget), 22.0);
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
			gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);

			widget = GTK_WIDGET (gtk_builder_get_object (builder, "tunmtu_spinbutton"));
			gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget), (gdouble) tmp);
			gtk_widget_set_sensitive (widget, TRUE);
		}
	} else {
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), FALSE);

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "tunmtu_spinbutton"));
		gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget), 1500.0);
		gtk_widget_set_sensitive (widget, FALSE);
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "extra_opts_checkbutton"));
	g_assert (widget);
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (extra_opts_toggled_cb), builder);

	value = g_hash_table_lookup (hash, NM_SSH_KEY_EXTRA_OPTS);
	if (value && strlen (value)) {
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "extra_opts_entry"));
		gtk_entry_set_text (GTK_ENTRY (widget), value);
		gtk_widget_set_sensitive (widget, TRUE);
	} else {
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), FALSE);

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "extra_opts_entry"));
		gtk_entry_set_text (GTK_ENTRY (widget), "");
		gtk_widget_set_sensitive (widget, FALSE);
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_tun_checkbutton"));
	g_assert (widget);
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (remote_tun_toggled_cb), builder);

	value = g_hash_table_lookup (hash, NM_SSH_KEY_REMOTE_TUN);
	if (value && strlen (value)) {
		errno = 0;
		tmp = strtol (value, NULL, 10);
		if (errno == 0 && tmp > 0 && tmp < 256) {
			gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);

			widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_tun_spinbutton"));
			gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget), (gdouble) tmp);
		}
		gtk_widget_set_sensitive (widget, TRUE);
	} else {
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), FALSE);

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_tun_spinbutton"));
		gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget), 100.0);
		gtk_widget_set_sensitive (widget, FALSE);
	}

out:
	g_free (ui_file);
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
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
		int tunmtu_size;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "tunmtu_spinbutton"));
		tunmtu_size = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));
		g_hash_table_insert (hash, g_strdup (NM_SSH_KEY_TUNNEL_MTU), g_strdup_printf ("%d", tunmtu_size));
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "port_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
		int port;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "port_spinbutton"));
		port = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));
		g_hash_table_insert (hash, g_strdup (NM_SSH_KEY_PORT), g_strdup_printf ("%d", port));
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "extra_opts_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
		const gchar *extra_options;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "extra_opts_entry"));
		extra_options = gtk_entry_get_text (GTK_ENTRY (widget));
		g_hash_table_insert (hash, g_strdup (NM_SSH_KEY_EXTRA_OPTS), g_strdup(extra_options));
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_tun_checkbutton"));
	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget))) {
		int remote_tun;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_tun_spinbutton"));
		remote_tun = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));
		g_hash_table_insert (hash, g_strdup (NM_SSH_KEY_REMOTE_TUN), g_strdup_printf ("%d", remote_tun));
	}

	return hash;
}

