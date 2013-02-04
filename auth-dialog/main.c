/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager Wireless Applet -- Display wireless access points and allow user control
 *
 * Dan Williams <dcbw@redhat.com>
 * Tim Niemueller <tim@niemueller.de>
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
 * (C) Copyright 2004 - 2008 Red Hat, Inc.
 *               2005 Tim Niemueller [www.niemueller.de]
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <glib/gi18n.h>
#include <gtk/gtk.h>
#include <gnome-keyring.h>
#include <gnome-keyring-memory.h>
#include <nm-setting-vpn.h>
#include <nm-setting-connection.h>
#include <nm-vpn-plugin-utils.h>

#include "common/utils.h"
#include "src/nm-ssh-service.h"
#include "vpn-password-dialog.h"

#define KEYRING_UUID_TAG "connection-uuid"
#define KEYRING_SN_TAG "setting-name"
#define KEYRING_SK_TAG "setting-key"

static char *
keyring_lookup_secret (const char *uuid, const char *secret_name)
{
	GList *found_list = NULL;
	GnomeKeyringResult ret;
	GnomeKeyringFound *found;
	char *secret = NULL;

	ret = gnome_keyring_find_itemsv_sync (GNOME_KEYRING_ITEM_GENERIC_SECRET,
	                                      &found_list,
	                                      KEYRING_UUID_TAG,
	                                      GNOME_KEYRING_ATTRIBUTE_TYPE_STRING,
	                                      uuid,
	                                      KEYRING_SN_TAG,
	                                      GNOME_KEYRING_ATTRIBUTE_TYPE_STRING,
	                                      NM_SETTING_VPN_SETTING_NAME,
	                                      KEYRING_SK_TAG,
	                                      GNOME_KEYRING_ATTRIBUTE_TYPE_STRING,
	                                      secret_name,
	                                      NULL);
	if (ret == GNOME_KEYRING_RESULT_OK && found_list) {
		found = g_list_nth_data (found_list, 0);
		secret = gnome_keyring_memory_strdup (found->secret);
	}

	gnome_keyring_found_list_free (found_list);
	return secret;
}

static gboolean
get_secrets (const char *vpn_name,
             const char *vpn_uuid,
             gboolean need_password,
             gboolean need_certpass,
             gboolean retry,
             gboolean allow_interaction,
             const char *in_pass,
             NMSettingSecretFlags pw_flags,
             char **out_password,
             const char *in_certpass,
             NMSettingSecretFlags cp_flags,
             char **out_certpass)
{
	VpnPasswordDialog *dialog;
	char *prompt, *password = NULL, *certpass = NULL;
	gboolean success = FALSE, need_secret = FALSE;

	g_return_val_if_fail (vpn_name != NULL, FALSE);
	g_return_val_if_fail (vpn_uuid != NULL, FALSE);
	g_return_val_if_fail (out_password != NULL, FALSE);
	g_return_val_if_fail (out_certpass != NULL, FALSE);

	if (need_password) {
		if (!(pw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED)) {
			if (in_pass)
				password = gnome_keyring_memory_strdup (in_pass);
			else
				password = keyring_lookup_secret (vpn_uuid, NM_SSH_KEY_PASSWORD);
		}
		if (!password && !(pw_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED))
			need_secret = TRUE;
	}

	if (need_certpass) {
		if (!(cp_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED)) {
			if (in_certpass)
				certpass = gnome_keyring_memory_strdup (in_certpass);
			else
				certpass = keyring_lookup_secret (vpn_uuid, NM_SSH_KEY_CERTPASS);
		}
		if (!certpass && !(cp_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED))
			need_secret = TRUE;
	}

	/* Either interaction is not allowed so pass back any passwords we have
	 * without asking the user, or we've got all the passwords we need already.
	 */
	if (allow_interaction == FALSE || (!need_secret && !retry)) {
		if (need_password)
			*out_password = password;
		if (need_certpass)
			*out_certpass = certpass;
		return TRUE;
	}

	prompt = g_strdup_printf (_("You need to authenticate to access the Virtual Private Network '%s'."), vpn_name);
	dialog = VPN_PASSWORD_DIALOG (vpn_password_dialog_new (_("Authenticate VPN"), prompt, NULL));
	g_free (prompt);

	/* pre-fill dialog with the password */
	if (need_password && need_certpass) {
		vpn_password_dialog_set_show_password_secondary (dialog, TRUE);
		vpn_password_dialog_set_password_secondary_label (dialog, _("Certificate pass_word:") );

		/* if retrying, put in the passwords from the keyring */
		if (password)
			vpn_password_dialog_set_password (dialog, password);
		if (certpass)
			vpn_password_dialog_set_password_secondary (dialog, certpass);
	} else {
		vpn_password_dialog_set_show_password_secondary (dialog, FALSE);
		if (need_password) {
			/* if retrying, put in the passwords from the keyring */
			if (password)
				vpn_password_dialog_set_password (dialog, password);
		} else if (need_certpass) {
			vpn_password_dialog_set_password_label (dialog, _("Certificate password:"));
			/* if retrying, put in the passwords from the keyring */
			if (certpass)
				vpn_password_dialog_set_password (dialog, certpass);
		}
	}

	if (password)
		gnome_keyring_memory_free (password);
	if (certpass)
		gnome_keyring_memory_free (certpass);

	gtk_widget_show (GTK_WIDGET (dialog));

	if (vpn_password_dialog_run_and_block (dialog)) {
		if (need_password)
			*out_password = gnome_keyring_memory_strdup (vpn_password_dialog_get_password (dialog));
		if (need_certpass) {
			if (need_password)
				*out_certpass = gnome_keyring_memory_strdup (vpn_password_dialog_get_password_secondary (dialog));
			else
				*out_certpass = gnome_keyring_memory_strdup (vpn_password_dialog_get_password (dialog));
		}

		success = TRUE;
	}

	gtk_widget_destroy (GTK_WIDGET (dialog));

	return success;
}

static void
get_password_types (GHashTable *data,
                    gboolean *out_need_password,
                    gboolean *out_need_certpass)
{
	const char *ctype, *val;
	NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;

	ctype = g_hash_table_lookup (data, NM_SSH_KEY_CONNECTION_TYPE);
	g_return_if_fail (ctype != NULL);

	if (!strcmp (ctype, NM_SSH_CONTYPE_TLS) || !strcmp (ctype, NM_SSH_CONTYPE_PASSWORD_TLS)) {
		/* Normal user password */
		nm_vpn_plugin_utils_get_secret_flags (data, NM_SSH_KEY_PASSWORD, &flags);
		if (   !strcmp (ctype, NM_SSH_CONTYPE_PASSWORD_TLS)
		    && !(flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED))
			*out_need_password = TRUE;

		/* Encrypted private key password */
		val = g_hash_table_lookup (data, NM_SSH_KEY_KEY);
		if (val)
			*out_need_certpass = is_encrypted (val);
	} else if (!strcmp (ctype, NM_SSH_CONTYPE_PASSWORD)) {
		nm_vpn_plugin_utils_get_secret_flags (data, NM_SSH_KEY_PASSWORD, &flags);
		if (!(flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED))
			*out_need_password = TRUE;
	}
}

static void
wait_for_quit (void)
{
	GString *str;
	char c;
	ssize_t n;
	time_t start;

	str = g_string_sized_new (10);
	start = time (NULL);
	do {
		errno = 0;
		n = read (0, &c, 1);
		if (n == 0 || (n < 0 && errno == EAGAIN))
			g_usleep (G_USEC_PER_SEC / 10);
		else if (n == 1) {
			g_string_append_c (str, c);
			if (strstr (str->str, "QUIT") || (str->len > 10))
				break;
		} else
			break;
	} while (time (NULL) < start + 20);
	g_string_free (str, TRUE);
}

int 
main (int argc, char *argv[])
{
	gboolean retry = FALSE, allow_interaction = FALSE;
	gchar *vpn_name = NULL;
	gchar *vpn_uuid = NULL;
	gchar *vpn_service = NULL;
	GHashTable *data = NULL, *secrets = NULL;
	gboolean need_password = FALSE, need_certpass = FALSE;
	char *new_password = NULL, *new_certpass = NULL;
	NMSettingSecretFlags pw_flags = NM_SETTING_SECRET_FLAG_NONE;
	NMSettingSecretFlags cp_flags = NM_SETTING_SECRET_FLAG_NONE;
	GOptionContext *context;
	GOptionEntry entries[] = {
			{ "reprompt", 'r', 0, G_OPTION_ARG_NONE, &retry, "Reprompt for passwords", NULL},
			{ "uuid", 'u', 0, G_OPTION_ARG_STRING, &vpn_uuid, "UUID of VPN connection", NULL},
			{ "name", 'n', 0, G_OPTION_ARG_STRING, &vpn_name, "Name of VPN connection", NULL},
			{ "service", 's', 0, G_OPTION_ARG_STRING, &vpn_service, "VPN service type", NULL},
			{ "allow-interaction", 'i', 0, G_OPTION_ARG_NONE, &allow_interaction, "Allow user interaction", NULL},
			{ NULL }
		};

	bindtextdomain (GETTEXT_PACKAGE, NULL);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);

	gtk_init (&argc, &argv);

	context = g_option_context_new ("- ssh auth dialog");
	g_option_context_add_main_entries (context, entries, GETTEXT_PACKAGE);
	g_option_context_parse (context, &argc, &argv, NULL);
	g_option_context_free (context);

	if (vpn_uuid == NULL || vpn_name == NULL || vpn_service == NULL) {
		fprintf (stderr, "Have to supply ID, name, and service\n");
		return EXIT_FAILURE;
	}

	if (strcmp (vpn_service, NM_DBUS_SERVICE_SSH) != 0) {
		fprintf (stderr, "This dialog only works with the '%s' service\n", NM_DBUS_SERVICE_SSH);
		return EXIT_FAILURE;
	}

	if (!nm_vpn_plugin_utils_read_vpn_details (0, &data, &secrets)) {
		fprintf (stderr, "Failed to read '%s' (%s) data and secrets from stdin.\n",
		         vpn_name, vpn_uuid);
		return 1;
	}

	get_password_types (data, &need_password, &need_certpass);
	if (!need_password && !need_certpass) {
		printf ("%s\n%s\n\n\n", NM_SSH_KEY_NOSECRET, "true");
		return 0;
	}

	nm_vpn_plugin_utils_get_secret_flags (data, NM_SSH_KEY_PASSWORD, &pw_flags);
	nm_vpn_plugin_utils_get_secret_flags (data, NM_SSH_KEY_CERTPASS, &cp_flags);
	if (!get_secrets (vpn_name,
	                  vpn_uuid,
	                  need_password,
	                  need_certpass,
	                  retry,
	                  allow_interaction,
	                  g_hash_table_lookup (secrets, NM_SSH_KEY_PASSWORD),
	                  pw_flags,
	                  &new_password,
	                  g_hash_table_lookup (secrets, NM_SSH_KEY_CERTPASS),
	                  cp_flags,
	                  &new_certpass))
		return 1;  /* canceled */

	if (need_password && new_password)
		printf ("%s\n%s\n", NM_SSH_KEY_PASSWORD, new_password);
	if (need_certpass && new_certpass)
		printf ("%s\n%s\n", NM_SSH_KEY_CERTPASS, new_certpass);
	printf ("\n\n");

	if (new_password)
		gnome_keyring_memory_free (new_password);
	if (new_certpass)
		gnome_keyring_memory_free (new_certpass);

	/* for good measure, flush stdout since Kansas is going Bye-Bye */
	fflush (stdout);

	/* Wait for quit signal */
	wait_for_quit ();

	if (data)
		g_hash_table_unref (data);
	if (secrets)
		g_hash_table_unref (secrets);
	return 0;
}
