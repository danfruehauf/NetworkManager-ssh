/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager Wireless Applet -- Display wireless access points and allow user control
 *
 * Dan Fruehauf <malkodan@gmail.com>
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
 * (C) Copyright 2013 Dan Fruehauf <malkodan@gmail.com>
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <glib/gi18n.h>
#include <gtk/gtk.h>

#include <libsecret/secret.h>

#include <nm-setting-vpn.h>
#include <nm-vpn-plugin-utils.h>

#include "src/nm-ssh-service.h"
#include "vpn-password-dialog.h"

#define KEYRING_UUID_TAG "connection-uuid"
#define KEYRING_SN_TAG "setting-name"
#define KEYRING_SK_TAG "setting-key"

#define UI_KEYFILE_GROUP "VPN Plugin UI"

static const SecretSchema network_manager_secret_schema = {
	"org.freedesktop.NetworkManager.Connection",
	SECRET_SCHEMA_DONT_MATCH_NAME,
	{
		{ KEYRING_UUID_TAG, SECRET_SCHEMA_ATTRIBUTE_STRING },
		{ KEYRING_SN_TAG, SECRET_SCHEMA_ATTRIBUTE_STRING },
		{ KEYRING_SK_TAG, SECRET_SCHEMA_ATTRIBUTE_STRING },
		{ NULL, 0 },
	}
};


static char *
keyring_lookup_secret (const char *uuid, const char *secret_name)
{
	GHashTable *attrs;
	GList *list;
	char *secret = NULL;

	attrs = secret_attributes_build (&network_manager_secret_schema,
									 KEYRING_UUID_TAG, uuid,
									 KEYRING_SN_TAG, NM_SETTING_VPN_SETTING_NAME,
									 KEYRING_SK_TAG, secret_name,
									 NULL);

	list = secret_service_search_sync (NULL, &network_manager_secret_schema, attrs,
									   SECRET_SEARCH_ALL |
									   SECRET_SEARCH_UNLOCK |
									   SECRET_SEARCH_LOAD_SECRETS,
									   NULL, NULL);

	if (list && list->data) {
		SecretItem *item = list->data;
		SecretValue *value = secret_item_get_secret (item);

		if (value) {
			secret = g_strdup (secret_value_get (value, NULL));
			secret_value_unref (value);
		}
	}

	g_list_free_full (list, g_object_unref);
	g_hash_table_unref (attrs);
	return secret;
}

static void
keyfile_add_entry_info (GKeyFile    *keyfile,
                        const gchar *key,
                        const gchar *value,
                        const gchar *label,
                        gboolean     is_secret,
                        gboolean     should_ask)
{
	g_key_file_set_string (keyfile, key, "Value", value);
	g_key_file_set_string (keyfile, key, "Label", label);
	g_key_file_set_boolean (keyfile, key, "IsSecret", is_secret);
	g_key_file_set_boolean (keyfile, key, "ShouldAsk", should_ask);
}

static void
keyfile_print_stdout (GKeyFile *keyfile)
{
	gchar *data;
	gsize length;

	data = g_key_file_to_data (keyfile, &length, NULL);

	fputs (data, stdout);

	g_free (data);
}

static gboolean
get_secrets (const char *vpn_uuid,
             const char *vpn_name,
             gboolean retry,
             gboolean allow_interaction,
             gboolean external_ui_mode,
             const char *in_pw,
             char **out_pw,
             NMSettingSecretFlags pw_flags)
{
	VpnPasswordDialog *dialog;
	char *prompt, *pw = NULL;
	const char *new_password = NULL;

	g_return_val_if_fail (vpn_uuid != NULL, FALSE);
	g_return_val_if_fail (vpn_name != NULL, FALSE);
	g_return_val_if_fail (out_pw != NULL, FALSE);
	g_return_val_if_fail (*out_pw == NULL, FALSE);

	/* Get the existing secret, if any */
	if (   !(pw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED)
	    && !(pw_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)) {
		if (in_pw)
			pw = g_strdup (in_pw);
		else
			pw = keyring_lookup_secret (vpn_uuid, NM_SSH_KEY_PASSWORD);
	}

	/* Don't ask if the passwords is unused */
	if (pw_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED) {
		g_free (pw);
		return TRUE;
	}

	/* Otherwise, we have no saved password, or the password flags indicated
	 * that the password should never be saved.
	 */
	prompt = g_strdup_printf (_("You need to authenticate to access the Virtual Private Network '%s'."), vpn_name);

	if (external_ui_mode) {
		GKeyFile *keyfile;

		keyfile = g_key_file_new ();

		g_key_file_set_integer (keyfile, UI_KEYFILE_GROUP, "Version", 2);
		g_key_file_set_string (keyfile, UI_KEYFILE_GROUP, "Description", prompt);
		g_key_file_set_string (keyfile, UI_KEYFILE_GROUP, "Title", _("Authenticate VPN"));

		keyfile_add_entry_info (keyfile, NM_SSH_KEY_PASSWORD, pw ? pw : "", _("Password:"), TRUE, allow_interaction);

		keyfile_print_stdout (keyfile);
		g_key_file_unref (keyfile);
		goto out;
	} else if (   allow_interaction == FALSE
	           || (!retry && pw && !(pw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED))) {
		/* If interaction isn't allowed, just return existing secrets.
		 * Also, don't ask the user if we don't need a new password (ie, !retry),
		 * we have an existing PW, and the password is saved.
		 */

		*out_pw = pw;
		g_free (prompt);
		return TRUE;
	}


	dialog = (VpnPasswordDialog *) vpn_password_dialog_new (_("Authenticate VPN"), prompt, NULL);

	vpn_password_dialog_set_show_password_secondary (dialog, FALSE);

	/* pre-fill dialog with the password */
	if (pw && !(pw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED))
		vpn_password_dialog_set_password (dialog, pw);

	gtk_widget_show (GTK_WIDGET (dialog));

	if (vpn_password_dialog_run_and_block (dialog)) {

		new_password = vpn_password_dialog_get_password (dialog);
		if (new_password)
			*out_pw = g_strdup (new_password);
	}

	gtk_widget_hide (GTK_WIDGET (dialog));
	gtk_widget_destroy (GTK_WIDGET (dialog));

 out:
	g_free (prompt);

	return TRUE;
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
	gboolean retry = FALSE, allow_interaction = FALSE, external_ui_mode = FALSE;
	char *vpn_name = NULL, *vpn_uuid = NULL, *vpn_service = NULL, *password = NULL;
	const char *auth_type, *password_key;
	GHashTable *data = NULL, *secrets = NULL;
	NMSettingSecretFlags pw_flags = NM_SETTING_SECRET_FLAG_NONE;
	GOptionContext *context;
	GOptionEntry entries[] = {
			{ "reprompt", 'r', 0, G_OPTION_ARG_NONE, &retry, "Reprompt for passwords", NULL},
			{ "uuid", 'u', 0, G_OPTION_ARG_STRING, &vpn_uuid, "UUID of VPN connection", NULL},
			{ "name", 'n', 0, G_OPTION_ARG_STRING, &vpn_name, "Name of VPN connection", NULL},
			{ "service", 's', 0, G_OPTION_ARG_STRING, &vpn_service, "VPN service type", NULL},
			{ "allow-interaction", 'i', 0, G_OPTION_ARG_NONE, &allow_interaction, "Allow user interaction", NULL},
			{ "external-ui-mode", 0, 0, G_OPTION_ARG_NONE, &external_ui_mode, "External UI mode", NULL},
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

	if (!vpn_uuid || !vpn_service || !vpn_name) {
		fprintf (stderr, "Have to supply ID, name, and service\n");
		return 1;
	}

	if (strncmp (vpn_service, NM_DBUS_SERVICE_SSH, strlen(NM_DBUS_SERVICE_SSH)) != 0) {
		fprintf (stderr, "This dialog only works with the '%s' service\n", NM_DBUS_SERVICE_SSH);
		return 1;
	}

	if (!nm_vpn_plugin_utils_read_vpn_details (0, &data, &secrets)) {
		fprintf (stderr, "Failed to read '%s' (%s) data and secrets from stdin.\n",
		         vpn_name, vpn_uuid);
		return 1;
	}

	/* Avoid awkwardness if auth_type equals NULL, which can happen:
	 * https://bugzilla.redhat.com/show_bug.cgi?id=1056810 */
	auth_type = g_hash_table_lookup (data, NM_SSH_KEY_AUTH_TYPE);
	if (!auth_type) {
		fprintf (stderr, "Authentication type not specified in configuration\n");
		return 1;
	}

	/* Depending on auth type see if we need a password */
	if (strncmp (auth_type, NM_SSH_AUTH_TYPE_PASSWORD, strlen(NM_SSH_AUTH_TYPE_PASSWORD)) == 0) {
		/* FIXME one day... */
		nm_vpn_plugin_utils_get_secret_flags (secrets, NM_SSH_KEY_PASSWORD, &pw_flags);
		password_key = NM_SSH_KEY_PASSWORD;
		if (!get_secrets (vpn_uuid, vpn_name, retry, allow_interaction, external_ui_mode,
			g_hash_table_lookup (secrets, NM_SSH_KEY_PASSWORD),
			&password,
			pw_flags))
		return 1;
	} else if (strncmp (auth_type, NM_SSH_AUTH_TYPE_KEY, strlen(NM_SSH_AUTH_TYPE_KEY)) == 0) {
		/* FIXME ask for password if key is encrypted */
	} else if (strncmp (auth_type, NM_SSH_AUTH_TYPE_SSH_AGENT, strlen(NM_SSH_AUTH_TYPE_SSH_AGENT)) == 0) {
		/* Probe the SSH agent socket */
		password = g_strdup (getenv (SSH_AUTH_SOCK));
		if (password && strlen (password)) {
			password_key = NM_SSH_KEY_SSH_AUTH_SOCK;
		} else {
			GtkWidget *dialog;
			dialog = gtk_message_dialog_new(NULL,
				GTK_DIALOG_MODAL,
				GTK_MESSAGE_WARNING,
				GTK_BUTTONS_OK,
				_("Couldn't find '%s' environment variable.\n\nIs ssh-agent running?"), SSH_AUTH_SOCK);
			gtk_window_set_title(GTK_WINDOW(dialog), "Warning");
			gtk_dialog_run(GTK_DIALOG(dialog));
			gtk_widget_destroy(dialog);
	
			return 1;
		}
	} else {
		fprintf (stderr, "Unknown authentication method required: '%s'.\n", auth_type);
		return 1;
	}

	if (!external_ui_mode) {
		/* dump the passwords to stdout */
		if (password)
			printf ("%s\n%s\n", password_key, password);
		printf ("\n\n");

		g_free (password);

		/* for good measure, flush stdout since Kansas is going Bye-Bye */
		fflush (stdout);

		/* Wait for quit signal */
		wait_for_quit ();
	}

	if (data)
		g_hash_table_unref (data);
	if (secrets)
		g_hash_table_unref (secrets);
	return 0;
}
