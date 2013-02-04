/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * Copyright (C) 2009 Dan Williams, <dcbw@redhat.com>
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
 */

#include <string.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <locale.h>

#include <nm-utils.h>
#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>
#include <nm-setting-vpn.h>

#define NM_VPN_API_SUBJECT_TO_CHANGE
#include <nm-vpn-plugin-ui-interface.h>

#include "nm-test-helpers.h"
#include "properties/nm-ssh.h"
#include "src/nm-ssh-service.h"

static NMConnection *
get_basic_connection (const char *detail,
                      NMVpnPluginUiInterface *plugin,
                      const char *dir,
                      const char *filename)
{
	NMConnection *connection;
	GError *error = NULL;
	char *pcf;

	pcf = g_build_path ("/", dir, filename, NULL);
	ASSERT (pcf != NULL,
	        "basic", "failed to create pcf path");

	connection = nm_vpn_plugin_ui_interface_import (plugin, pcf, &error);
	if (error)
		FAIL ("basic", "error importing %s: %s", pcf, error->message);
	ASSERT (connection != NULL,
	        "basic", "error importing %s: (unknown)", pcf);

	g_free (pcf);
	return connection;
}

static void
test_item (const char *test,
           NMSettingVPN *s_vpn,
           const char *item,
           const char *expected)
{
	const char *value;

	ASSERT (s_vpn != NULL, test, "missing 'vpn' setting");

	value = nm_setting_vpn_get_data_item (s_vpn, item);
	if (expected == NULL) {
		ASSERT (value == NULL, test, "unexpected '%s' item value (found '%s', expected NULL",
		        item, value);
		return;
	}

	ASSERT (value != NULL, test, "missing '%s' item value", item);
	ASSERT (strcmp (value, expected) == 0, test,
	        "unexpected '%s' secret value (found '%s', expected '%s')",
	        item, value, expected);
}

static void
test_secret (const char *test,
             NMSettingVPN *s_vpn,
             const char *item,
             const char *expected)
{
	const char *value;

	ASSERT (s_vpn != NULL, test, "missing 'vpn' setting");

	value = nm_setting_vpn_get_secret (s_vpn, item);
	if (expected == NULL) {
		ASSERT (value == NULL, test, "unexpected '%s' secret value (found '%s', expected NULL",
		        item, value);
		return;
	}

	ASSERT (value != NULL, test, "missing '%s' secret value", item);
	ASSERT (strcmp (value, expected) == 0, test,
	        "unexpected '%s' secret value (found '%s', expected '%s')",
	        item, value, expected);
}

static void
test_password_import (NMVpnPluginUiInterface *plugin, const char *dir)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIP4Config *s_ip4;
	NMSettingVPN *s_vpn;
	const char *expected_id = "password";
	char *expected_cacert;

	connection = get_basic_connection ("password-import", plugin, dir, "password.conf");
	ASSERT (connection != NULL, "password-import", "failed to import connection");

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
	ASSERT (s_con != NULL,
	        "password-import", "missing 'connection' setting");

	ASSERT (strcmp (nm_setting_connection_get_id (s_con), expected_id) == 0,
	        "password-import", "unexpected connection ID");

	ASSERT (nm_setting_connection_get_uuid (s_con) == NULL,
	        "password-import", "unexpected valid UUID");

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG);
	ASSERT (s_ip4 == NULL,
	        "password-import", "unexpected 'ip4-config' setting");

	/* VPN setting */
	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);
	ASSERT (s_vpn != NULL,
	        "password-import", "missing 'vpn' setting");

	/* Data items */
	test_item ("password-import-data", s_vpn, NM_SSH_KEY_CONNECTION_TYPE, NM_SSH_CONTYPE_PASSWORD);
	test_item ("password-import-data", s_vpn, NM_SSH_KEY_TAP_DEV, NULL);
	test_item ("password-import-data", s_vpn, NM_SSH_KEY_PROTO_TCP, NULL);
	test_item ("password-import-data", s_vpn, NM_SSH_KEY_COMP_LZO, NULL);
	test_item ("password-import-data", s_vpn, NM_SSH_KEY_RENEG_SECONDS, "0");
	test_item ("password-import-data", s_vpn, NM_SSH_KEY_REMOTE, "test.server.com");
	test_item ("password-import-data", s_vpn, NM_SSH_KEY_PORT, "443");
	test_item ("password-import-data", s_vpn, NM_SSH_KEY_CERT, NULL);
	test_item ("password-import-data", s_vpn, NM_SSH_KEY_KEY, NULL);
	test_item ("password-import-data", s_vpn, NM_SSH_KEY_STATIC_KEY, NULL);
	test_item ("password-import-data", s_vpn, NM_SSH_KEY_STATIC_KEY_DIRECTION, NULL);
	test_item ("password-import-data", s_vpn, NM_SSH_KEY_TA, NULL);
	test_item ("password-import-data", s_vpn, NM_SSH_KEY_TA_DIR, NULL);
	test_item ("password-import-data", s_vpn, NM_SSH_KEY_CIPHER, "AES-256-CBC");
	test_item ("password-import-data", s_vpn, NM_SSH_KEY_LOCAL_IP, NULL);
	test_item ("password-import-data", s_vpn, NM_SSH_KEY_REMOTE_IP, NULL);
	test_item ("password-import-data", s_vpn, NM_SSH_KEY_AUTH, NULL);

	expected_cacert = g_strdup_printf ("%s/cacert.pem", dir);
	test_item ("password-import-data", s_vpn, NM_SSH_KEY_CA, expected_cacert);
	g_free (expected_cacert);

	/* Secrets */
	test_secret ("password-import-secrets", s_vpn, NM_SSH_KEY_PASSWORD, NULL);
	test_secret ("password-import-secrets", s_vpn, NM_SSH_KEY_CERTPASS, NULL);

	g_object_unref (connection);
}

static void
save_one_key (const char *key, const char *value, gpointer user_data)
{
	GSList **list = user_data;

	*list = g_slist_append (*list, g_strdup (key));
}

static void
remove_secrets (NMConnection *connection)
{
	NMSettingVPN *s_vpn;
	GSList *keys = NULL, *iter;

	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);
	if (!s_vpn)
		return;

	nm_setting_vpn_foreach_secret (s_vpn, save_one_key, &keys);
	for (iter = keys; iter; iter = g_slist_next (iter))
		nm_setting_vpn_remove_secret (s_vpn, (const char *) iter->data);

	g_slist_foreach (keys, (GFunc) g_free, NULL);
	g_slist_free (keys);
}

#define PASSWORD_EXPORTED_NAME "password.ovpntest"
static void
test_password_export (NMVpnPluginUiInterface *plugin, const char *dir, const char *tmpdir)
{
	NMConnection *connection;
	NMConnection *reimported;
	char *path;
	gboolean success;
	GError *error = NULL;

	connection = get_basic_connection ("password-export", plugin, dir, "password.conf");
	ASSERT (connection != NULL, "password-export", "failed to import connection");

	path = g_build_path ("/", tmpdir, PASSWORD_EXPORTED_NAME, NULL);
	success = nm_vpn_plugin_ui_interface_export (plugin, path, connection, &error);
	if (!success) {
		if (!error)
			FAIL ("password-export", "export failed with missing error");
		else
			FAIL ("password-export", "export failed: %s", error->message);
	}

	/* Now re-import it and compare the connections to ensure they are the same */
	reimported = get_basic_connection ("password-export", plugin, tmpdir, PASSWORD_EXPORTED_NAME);
	(void) unlink (path);
	ASSERT (reimported != NULL, "password-export", "failed to re-import connection");

	/* Clear secrets first, since they don't get exported, and thus would
	 * make the connection comparison below fail.
	 */
	remove_secrets (connection);

	ASSERT (nm_connection_compare (connection, reimported, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "password-export", "original and reimported connection differ");

	g_object_unref (reimported);
	g_object_unref (connection);
	g_free (path);
}

static void
test_tls_import (NMVpnPluginUiInterface *plugin, const char *dir)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIP4Config *s_ip4;
	NMSettingVPN *s_vpn;
	const char *expected_id = "tls";
	char *expected_path;

	connection = get_basic_connection ("tls-import", plugin, dir, "tls.ovpn");
	ASSERT (connection != NULL, "tls-import", "failed to import connection");

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
	ASSERT (s_con != NULL,
	        "tls-import", "missing 'connection' setting");

	ASSERT (strcmp (nm_setting_connection_get_id (s_con), expected_id) == 0,
	        "tls-import", "unexpected connection ID");

	ASSERT (nm_setting_connection_get_uuid (s_con) == NULL,
	        "tls-import", "unexpected valid UUID");

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG);
	ASSERT (s_ip4 == NULL,
	        "tls-import", "unexpected 'ip4-config' setting");

	/* VPN setting */
	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);
	ASSERT (s_vpn != NULL,
	        "tls-import", "missing 'vpn' setting");

	/* Data items */
	test_item ("tls-import-data", s_vpn, NM_SSH_KEY_CONNECTION_TYPE, NM_SSH_CONTYPE_TLS);
	test_item ("tls-import-data", s_vpn, NM_SSH_KEY_TAP_DEV, NULL);
	test_item ("tls-import-data", s_vpn, NM_SSH_KEY_PROTO_TCP, NULL);
	test_item ("tls-import-data", s_vpn, NM_SSH_KEY_COMP_LZO, "yes");
	test_item ("tls-import-data", s_vpn, NM_SSH_KEY_RENEG_SECONDS, NULL);
	test_item ("tls-import-data", s_vpn, NM_SSH_KEY_REMOTE, "173.8.149.245");
	test_item ("tls-import-data", s_vpn, NM_SSH_KEY_PORT, "1194");
	test_item ("tls-import-data", s_vpn, NM_SSH_KEY_STATIC_KEY, NULL);
	test_item ("tls-import-data", s_vpn, NM_SSH_KEY_STATIC_KEY_DIRECTION, NULL);
	test_item ("tls-import-data", s_vpn, NM_SSH_KEY_CIPHER, NULL);
	test_item ("tls-import-data", s_vpn, NM_SSH_KEY_LOCAL_IP, NULL);
	test_item ("tls-import-data", s_vpn, NM_SSH_KEY_REMOTE_IP, NULL);
	test_item ("tls-import-data", s_vpn, NM_SSH_KEY_AUTH, NULL);
	test_item ("tls-import-data", s_vpn, NM_SSH_KEY_TLS_REMOTE, "/CN=myvpn.company.com");

	expected_path = g_strdup_printf ("%s/keys/mg8.ca", dir);
	test_item ("tls-import-data", s_vpn, NM_SSH_KEY_CA, expected_path);
	g_free (expected_path);

	expected_path = g_strdup_printf ("%s/keys/clee.crt", dir);
	test_item ("tls-import-data", s_vpn, NM_SSH_KEY_CERT, expected_path);
	g_free (expected_path);

	expected_path = g_strdup_printf ("%s/keys/clee.key", dir);
	test_item ("tls-import-data", s_vpn, NM_SSH_KEY_KEY, expected_path);
	g_free (expected_path);

	expected_path = g_strdup_printf ("%s/keys/46.key", dir);
	test_item ("tls-import-data", s_vpn, NM_SSH_KEY_TA, expected_path);
	g_free (expected_path);
	test_item ("tls-import-data", s_vpn, NM_SSH_KEY_TA_DIR, "1");

	/* Secrets */
	test_secret ("tls-import-secrets", s_vpn, NM_SSH_KEY_PASSWORD, NULL);
	test_secret ("tls-import-secrets", s_vpn, NM_SSH_KEY_CERTPASS, NULL);

	g_object_unref (connection);
}

#define TLS_EXPORTED_NAME "tls.ovpntest"
static void
test_tls_export (NMVpnPluginUiInterface *plugin, const char *dir, const char *tmpdir)
{
	NMConnection *connection;
	NMConnection *reimported;
	char *path;
	gboolean success;
	GError *error = NULL;

	connection = get_basic_connection ("tls-export", plugin, dir, "tls.ovpn");
	ASSERT (connection != NULL, "tls-export", "failed to import connection");

	path = g_build_path ("/", tmpdir, TLS_EXPORTED_NAME, NULL);
	success = nm_vpn_plugin_ui_interface_export (plugin, path, connection, &error);
	if (!success) {
		if (!error)
			FAIL ("tls-export", "export failed with missing error");
		else
			FAIL ("tls-export", "export failed: %s", error->message);
	}

	/* Now re-import it and compare the connections to ensure they are the same */
	reimported = get_basic_connection ("tls-export", plugin, tmpdir, TLS_EXPORTED_NAME);
	(void) unlink (path);
	ASSERT (reimported != NULL, "tls-export", "failed to re-import connection");

	/* Clear secrets first, since they don't get exported, and thus would
	 * make the connection comparison below fail.
	 */
	remove_secrets (connection);

	ASSERT (nm_connection_compare (connection, reimported, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "tls-export", "original and reimported connection differ");

	g_object_unref (reimported);
	g_object_unref (connection);
	g_free (path);
}

static void
test_pkcs12_import (NMVpnPluginUiInterface *plugin, const char *dir)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIP4Config *s_ip4;
	NMSettingVPN *s_vpn;
	const char *expected_id = "pkcs12";
	char *expected_path;

	connection = get_basic_connection ("pkcs12-import", plugin, dir, "pkcs12.ovpn");
	ASSERT (connection != NULL, "pkcs12-import", "failed to import connection");

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
	ASSERT (s_con != NULL,
	        "pkcs12-import", "missing 'connection' setting");

	ASSERT (strcmp (nm_setting_connection_get_id (s_con), expected_id) == 0,
	        "pkcs12-import", "unexpected connection ID");

	ASSERT (nm_setting_connection_get_uuid (s_con) == NULL,
	        "pkcs12-import", "unexpected valid UUID");

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG);
	ASSERT (s_ip4 == NULL,
	        "pkcs12-import", "unexpected 'ip4-config' setting");

	/* VPN setting */
	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);
	ASSERT (s_vpn != NULL,
	        "pkcs12-import", "missing 'vpn' setting");

	/* Data items */
	test_item ("pkcs12-import-data", s_vpn, NM_SSH_KEY_CONNECTION_TYPE, NM_SSH_CONTYPE_TLS);
	test_item ("pkcs12-import-data", s_vpn, NM_SSH_KEY_TAP_DEV, NULL);
	test_item ("pkcs12-import-data", s_vpn, NM_SSH_KEY_PROTO_TCP, NULL);
	test_item ("pkcs12-import-data", s_vpn, NM_SSH_KEY_COMP_LZO, "yes");
	test_item ("pkcs12-import-data", s_vpn, NM_SSH_KEY_RENEG_SECONDS, NULL);
	test_item ("pkcs12-import-data", s_vpn, NM_SSH_KEY_REMOTE, "173.8.149.245");
	test_item ("pkcs12-import-data", s_vpn, NM_SSH_KEY_PORT, "1194");
	test_item ("pkcs12-import-data", s_vpn, NM_SSH_KEY_STATIC_KEY, NULL);
	test_item ("pkcs12-import-data", s_vpn, NM_SSH_KEY_STATIC_KEY_DIRECTION, NULL);
	test_item ("pkcs12-import-data", s_vpn, NM_SSH_KEY_CIPHER, NULL);
	test_item ("pkcs12-import-data", s_vpn, NM_SSH_KEY_LOCAL_IP, NULL);
	test_item ("pkcs12-import-data", s_vpn, NM_SSH_KEY_REMOTE_IP, NULL);
	test_item ("pkcs12-import-data", s_vpn, NM_SSH_KEY_AUTH, NULL);

	expected_path = g_strdup_printf ("%s/keys/mine.p12", dir);
	test_item ("pkcs12-import-data", s_vpn, NM_SSH_KEY_CA, expected_path);
	g_free (expected_path);

	expected_path = g_strdup_printf ("%s/keys/mine.p12", dir);
	test_item ("pkcs12-import-data", s_vpn, NM_SSH_KEY_CERT, expected_path);
	g_free (expected_path);

	expected_path = g_strdup_printf ("%s/keys/mine.p12", dir);
	test_item ("pkcs12-import-data", s_vpn, NM_SSH_KEY_KEY, expected_path);
	g_free (expected_path);

	/* Secrets */
	test_secret ("pkcs12-import-secrets", s_vpn, NM_SSH_KEY_PASSWORD, NULL);
	test_secret ("pkcs12-import-secrets", s_vpn, NM_SSH_KEY_CERTPASS, NULL);

	g_object_unref (connection);
}

#define PKCS12_EXPORTED_NAME "pkcs12.ovpntest"
static void
test_pkcs12_export (NMVpnPluginUiInterface *plugin, const char *dir, const char *tmpdir)
{
	NMConnection *connection;
	NMConnection *reimported;
	char *path;
	gboolean success;
	GError *error = NULL;

	connection = get_basic_connection ("pkcs12-export", plugin, dir, "pkcs12.ovpn");
	ASSERT (connection != NULL, "pkcs12-export", "failed to import connection");

	path = g_build_path ("/", tmpdir, PKCS12_EXPORTED_NAME, NULL);
	success = nm_vpn_plugin_ui_interface_export (plugin, path, connection, &error);
	if (!success) {
		if (!error)
			FAIL ("pkcs12-export", "export failed with missing error");
		else
			FAIL ("pkcs12-export", "export failed: %s", error->message);
	}

	/* Now re-import it and compare the connections to ensure they are the same */
	reimported = get_basic_connection ("pkcs12-export", plugin, tmpdir, PKCS12_EXPORTED_NAME);
	(void) unlink (path);
	ASSERT (reimported != NULL, "pkcs12-export", "failed to re-import connection");

	/* Clear secrets first, since they don't get exported, and thus would
	 * make the connection comparison below fail.
	 */
	remove_secrets (connection);

	ASSERT (nm_connection_compare (connection, reimported, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "pkcs12-export", "original and reimported connection differ");

	g_object_unref (reimported);
	g_object_unref (connection);
	g_free (path);
}

static void
test_non_utf8_import (NMVpnPluginUiInterface *plugin, const char *dir)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingVPN *s_vpn;
	const char *expected_cacert = "Attätaenko.pem";
	char *expected_path;
	const char *charset = NULL;

	/* Change charset to ISO-8859-15 to match iso885915.ovpn */
	g_get_charset (&charset);
	setlocale (LC_ALL, "de_DE@euro");
	connection = get_basic_connection ("non-utf8-import", plugin, dir, "iso885915.ovpn");
	setlocale (LC_ALL, charset);

	ASSERT (connection != NULL, "non-utf8-import", "failed to import connection");

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
	ASSERT (s_con != NULL,
	        "non-utf8-import", "missing 'connection' setting");

	ASSERT (strcmp (nm_setting_connection_get_id (s_con), "iso885915") == 0,
	        "non-utf8-import", "unexpected connection ID");

	ASSERT (nm_setting_connection_get_uuid (s_con) == NULL,
	        "non-utf8-import", "unexpected valid UUID");

	/* VPN setting */
	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);
	ASSERT (s_vpn != NULL,
	        "non-utf8-import", "missing 'vpn' setting");

	expected_path = g_strdup_printf ("%s/%s", dir, expected_cacert);
	test_item ("non-utf8-import-data", s_vpn, NM_SSH_KEY_CA, expected_path);
	g_free (expected_path);

	g_object_unref (connection);
}

static void
test_static_key_import (NMVpnPluginUiInterface *plugin, const char *dir)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingIP4Config *s_ip4;
	NMSettingVPN *s_vpn;
	const char *expected_id = "static";
	char *expected_path;

	connection = get_basic_connection ("static-key-import", plugin, dir, "static.ovpn");
	ASSERT (connection != NULL, "static-key-import", "failed to import connection");

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
	ASSERT (s_con != NULL,
	        "static-key-import", "missing 'connection' setting");

	ASSERT (strcmp (nm_setting_connection_get_id (s_con), expected_id) == 0,
	        "static-key-import", "unexpected connection ID");

	ASSERT (nm_setting_connection_get_uuid (s_con) == NULL,
	        "static-key-import", "unexpected valid UUID");

	/* IP4 setting */
	s_ip4 = (NMSettingIP4Config *) nm_connection_get_setting (connection, NM_TYPE_SETTING_IP4_CONFIG);
	ASSERT (s_ip4 == NULL,
	        "static-key-import", "unexpected 'ip4-config' setting");

	/* VPN setting */
	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);
	ASSERT (s_vpn != NULL,
	        "static-key-import", "missing 'vpn' setting");

	/* Data items */
	test_item ("static-key-import-data", s_vpn, NM_SSH_KEY_CONNECTION_TYPE, NM_SSH_CONTYPE_STATIC_KEY);
	test_item ("static-key-import-data", s_vpn, NM_SSH_KEY_TAP_DEV, NULL);
	test_item ("static-key-import-data", s_vpn, NM_SSH_KEY_PROTO_TCP, NULL);
	test_item ("static-key-import-data", s_vpn, NM_SSH_KEY_COMP_LZO, NULL);
	test_item ("static-key-import-data", s_vpn, NM_SSH_KEY_RENEG_SECONDS, NULL);
	test_item ("static-key-import-data", s_vpn, NM_SSH_KEY_REMOTE, "10.11.12.13");
	test_item ("static-key-import-data", s_vpn, NM_SSH_KEY_PORT, NULL);
	test_item ("static-key-import-data", s_vpn, NM_SSH_KEY_STATIC_KEY_DIRECTION, "1");
	test_item ("static-key-import-data", s_vpn, NM_SSH_KEY_TA, NULL);
	test_item ("static-key-import-data", s_vpn, NM_SSH_KEY_TA_DIR, NULL);
	test_item ("static-key-import-data", s_vpn, NM_SSH_KEY_CIPHER, NULL);
	test_item ("static-key-import-data", s_vpn, NM_SSH_KEY_LOCAL_IP, "10.8.0.2");
	test_item ("static-key-import-data", s_vpn, NM_SSH_KEY_REMOTE_IP, "10.8.0.1");
	test_item ("static-key-import-data", s_vpn, NM_SSH_KEY_AUTH, NULL);

	expected_path = g_strdup_printf ("%s/static.key", dir);
	test_item ("static-key-import-data", s_vpn, NM_SSH_KEY_STATIC_KEY, expected_path);
	g_free (expected_path);

	/* Secrets */
	test_secret ("static-key-import-secrets", s_vpn, NM_SSH_KEY_PASSWORD, NULL);
	test_secret ("static-key-import-secrets", s_vpn, NM_SSH_KEY_CERTPASS, NULL);

	g_object_unref (connection);
}

#define STATIC_KEY_EXPORTED_NAME "static.ovpntest"
static void
test_static_key_export (NMVpnPluginUiInterface *plugin, const char *dir, const char *tmpdir)
{
	NMConnection *connection;
	NMConnection *reimported;
	char *path;
	gboolean success;
	GError *error = NULL;

	connection = get_basic_connection ("static-key-export", plugin, dir, "static.ovpn");
	ASSERT (connection != NULL, "static-key-export", "failed to import connection");

	path = g_build_path ("/", tmpdir, STATIC_KEY_EXPORTED_NAME, NULL);
	success = nm_vpn_plugin_ui_interface_export (plugin, path, connection, &error);
	if (!success) {
		if (!error)
			FAIL ("static-key-export", "export failed with missing error");
		else
			FAIL ("static-key-export", "export failed: %s", error->message);
	}

	/* Now re-import it and compare the connections to ensure they are the same */
	reimported = get_basic_connection ("static-key-export", plugin, tmpdir, STATIC_KEY_EXPORTED_NAME);
	(void) unlink (path);
	ASSERT (reimported != NULL, "static-key-export", "failed to re-import connection");

	/* Clear secrets first, since they don't get exported, and thus would
	 * make the connection comparison below fail.
	 */
	remove_secrets (connection);

	ASSERT (nm_connection_compare (connection, reimported, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "static-key-export", "original and reimported connection differ");

	g_object_unref (reimported);
	g_object_unref (connection);
	g_free (path);
}

static void
test_port_import (NMVpnPluginUiInterface *plugin,
                  const char *detail,
                  const char *dir,
                  const char *file,
                  const char *expected_id,
                  const char *expected_port)
{
	NMConnection *connection;
	NMSettingConnection *s_con;
	NMSettingVPN *s_vpn;

	connection = get_basic_connection (detail, plugin, dir, file);
	ASSERT (connection != NULL, detail, "failed to import connection");

	/* Connection setting */
	s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
	ASSERT (s_con != NULL,
	        detail, "missing 'connection' setting");

	ASSERT (strcmp (nm_setting_connection_get_id (s_con), expected_id) == 0,
	        detail, "unexpected connection ID");

	/* VPN setting */
	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);
	ASSERT (s_vpn != NULL,
	        detail, "missing 'vpn' setting");

	/* Data items */
	test_item (detail, s_vpn, NM_SSH_KEY_CONNECTION_TYPE, NM_SSH_CONTYPE_TLS);
	test_item (detail, s_vpn, NM_SSH_KEY_PORT, expected_port);

	g_object_unref (connection);
}

static void
test_port_export (NMVpnPluginUiInterface *plugin,
                  const char *detail,
                  const char *dir,
                  const char *tmpdir,
                  const char *file,
                  const char *exported_name)
{
	NMConnection *connection;
	NMConnection *reimported;
	char *path;
	gboolean success;
	GError *error = NULL;

	connection = get_basic_connection (detail, plugin, dir, file);
	ASSERT (connection != NULL, detail, "failed to import connection");

	path = g_build_path ("/", tmpdir, exported_name, NULL);
	success = nm_vpn_plugin_ui_interface_export (plugin, path, connection, &error);
	if (!success) {
		if (!error)
			FAIL (detail, "export failed with missing error");
		else
			FAIL (detail, "export failed: %s", error->message);
	}

	/* Now re-import it and compare the connections to ensure they are the same */
	reimported = get_basic_connection (detail, plugin, tmpdir, exported_name);
	(void) unlink (path);
	ASSERT (reimported != NULL, detail, "failed to re-import connection");

	/* Clear secrets first, since they don't get exported, and thus would
	 * make the connection comparison below fail.
	 */
	remove_secrets (connection);

	ASSERT (nm_connection_compare (connection, reimported, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        detail, "original and reimported connection differ");

	g_object_unref (reimported);
	g_object_unref (connection);
	g_free (path);
}

static void
test_tun_opts_import (NMVpnPluginUiInterface *plugin, const char *dir)
{
	NMConnection *connection;
	NMSettingVPN *s_vpn;

	connection = get_basic_connection ("tunopts-import", plugin, dir, "tun-opts.conf");
	ASSERT (connection != NULL, "tunopts-import", "failed to import connection");

	/* VPN setting */
	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);
	ASSERT (s_vpn != NULL,
	        "tunopts-import", "missing 'vpn' setting");

	/* Data items */
	test_item ("tunopts-import-data", s_vpn, NM_SSH_KEY_MSSFIX, "yes");
	test_item ("tunopts-import-data", s_vpn, NM_SSH_KEY_TUNNEL_MTU, "1300");
	test_item ("tunopts-import-data", s_vpn, NM_SSH_KEY_FRAGMENT_SIZE, "1200");

	g_object_unref (connection);
}

#define TUNOPTS_EXPORTED_NAME "tun-opts.ovpntest"
static void
test_tun_opts_export (NMVpnPluginUiInterface *plugin, const char *dir, const char *tmpdir)
{
	NMConnection *connection;
	NMConnection *reimported;
	char *path;
	gboolean success;
	GError *error = NULL;

	connection = get_basic_connection ("tunopts-export", plugin, dir, "tun-opts.conf");
	ASSERT (connection != NULL, "tunopts-export", "failed to import connection");

	path = g_build_path ("/", tmpdir, TUNOPTS_EXPORTED_NAME, NULL);
	success = nm_vpn_plugin_ui_interface_export (plugin, path, connection, &error);
	if (!success) {
		if (!error)
			FAIL ("tunopts-export", "export failed with missing error");
		else
			FAIL ("tunopts-export", "export failed: %s", error->message);
	}

	/* Now re-import it and compare the connections to ensure they are the same */
	reimported = get_basic_connection ("tunopts-export", plugin, tmpdir, TUNOPTS_EXPORTED_NAME);
	(void) unlink (path);
	ASSERT (reimported != NULL, "tunopts-export", "failed to re-import connection");

	/* Clear secrets first, since they don't get exported, and thus would
	 * make the connection comparison below fail.
	 */
	remove_secrets (connection);

	ASSERT (nm_connection_compare (connection, reimported, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "tunopts-export", "original and reimported connection differ");

	g_object_unref (reimported);
	g_object_unref (connection);
	g_free (path);
}

static void
test_proxy_http_import (NMVpnPluginUiInterface *plugin, const char *dir)
{
	NMConnection *connection;
	NMSettingVPN *s_vpn;

	connection = get_basic_connection ("proxy-http-import", plugin, dir, "proxy-http.ovpn");
	ASSERT (connection != NULL, "proxy-http-import", "failed to import connection");

	/* VPN setting */
	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);
	ASSERT (s_vpn != NULL,
	        "proxy-http-import", "missing 'vpn' setting");

	/* Data items */
	test_item ("proxy-http-import-data", s_vpn, NM_SSH_KEY_CONNECTION_TYPE, NM_SSH_CONTYPE_PASSWORD);
	test_item ("proxy-http-import-data", s_vpn, NM_SSH_KEY_TAP_DEV, NULL);
	test_item ("proxy-http-import-data", s_vpn, NM_SSH_KEY_PROTO_TCP, "yes");
	test_item ("proxy-http-import-data", s_vpn, NM_SSH_KEY_COMP_LZO, NULL);
	test_item ("proxy-http-import-data", s_vpn, NM_SSH_KEY_RENEG_SECONDS, "0");
	test_item ("proxy-http-import-data", s_vpn, NM_SSH_KEY_REMOTE, "test.server.com");
	test_item ("proxy-http-import-data", s_vpn, NM_SSH_KEY_PORT, "443");
	test_item ("proxy-http-import-data", s_vpn, NM_SSH_KEY_CERT, NULL);
	test_item ("proxy-http-import-data", s_vpn, NM_SSH_KEY_KEY, NULL);
	test_item ("proxy-http-import-data", s_vpn, NM_SSH_KEY_STATIC_KEY, NULL);
	test_item ("proxy-http-import-data", s_vpn, NM_SSH_KEY_STATIC_KEY_DIRECTION, NULL);
	test_item ("proxy-http-import-data", s_vpn, NM_SSH_KEY_TA, NULL);
	test_item ("proxy-http-import-data", s_vpn, NM_SSH_KEY_TA_DIR, NULL);
	test_item ("proxy-http-import-data", s_vpn, NM_SSH_KEY_CIPHER, "AES-256-CBC");
	test_item ("proxy-http-import-data", s_vpn, NM_SSH_KEY_LOCAL_IP, NULL);
	test_item ("proxy-http-import-data", s_vpn, NM_SSH_KEY_REMOTE_IP, NULL);
	test_item ("proxy-http-import-data", s_vpn, NM_SSH_KEY_AUTH, NULL);
	test_item ("proxy-http-import-data", s_vpn, NM_SSH_KEY_AUTH, NULL);
	test_item ("proxy-http-import-data", s_vpn, NM_SSH_KEY_PROXY_TYPE, "http");
	test_item ("proxy-http-import-data", s_vpn, NM_SSH_KEY_PROXY_SERVER, "10.1.1.1");
	test_item ("proxy-http-import-data", s_vpn, NM_SSH_KEY_PROXY_PORT, "8080");
	test_item ("proxy-http-import-data", s_vpn, NM_SSH_KEY_HTTP_PROXY_USERNAME, "myusername");
	test_secret ("proxy-http-import-secrets", s_vpn, NM_SSH_KEY_HTTP_PROXY_PASSWORD, "mypassword");

	g_object_unref (connection);
}

#define PROXY_HTTP_EXPORTED_NAME "proxy-http.ovpntest"
static void
test_proxy_http_export (NMVpnPluginUiInterface *plugin, const char *dir, const char *tmpdir)
{
	NMConnection *connection;
	NMConnection *reimported;
	char *path;
	gboolean success;
	GError *error = NULL;

	connection = get_basic_connection ("proxy-http-export", plugin, dir, "proxy-http.ovpn");
	ASSERT (connection != NULL, "proxy-http-export", "failed to import connection");

	path = g_build_path ("/", tmpdir, PROXY_HTTP_EXPORTED_NAME, NULL);
	success = nm_vpn_plugin_ui_interface_export (plugin, path, connection, &error);
	if (!success) {
		if (!error)
			FAIL ("proxy-http-export", "export failed with missing error");
		else
			FAIL ("proxy-http-export", "export failed: %s", error->message);
	}

	/* Now re-import it and compare the connections to ensure they are the same */
	reimported = get_basic_connection ("proxy-http-export", plugin, tmpdir, PROXY_HTTP_EXPORTED_NAME);
	(void) unlink (path);
	g_free (path);
	ASSERT (reimported != NULL, "proxy-http-export", "failed to re-import connection");

	ASSERT (nm_connection_compare (connection, reimported, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "proxy-http-export", "original and reimported connection differ");

	/* Unlink the proxy authfile */
	path = g_strdup_printf ("%s/%s-httpauthfile", tmpdir, PROXY_HTTP_EXPORTED_NAME);
	(void) unlink (path);
	g_free (path);

	g_object_unref (reimported);
	g_object_unref (connection);
}

static void
test_proxy_http_with_auth_import (NMVpnPluginUiInterface *plugin, const char *dir)
{
	NMConnection *connection;
	NMSettingVPN *s_vpn;

	connection = get_basic_connection ("proxy-http-with-auth-import", plugin, dir, "proxy-http-with-auth.ovpn");
	ASSERT (connection != NULL, "proxy-http-with-auth-import", "failed to import connection");

	/* VPN setting */
	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);
	ASSERT (s_vpn != NULL,
	        "proxy-http-with-auth-import", "missing 'vpn' setting");

	/* Data items */
	test_item ("proxy-http-with-auth-import-data", s_vpn, NM_SSH_KEY_CONNECTION_TYPE, NM_SSH_CONTYPE_PASSWORD);
	test_item ("proxy-http-with-auth-import-data", s_vpn, NM_SSH_KEY_TAP_DEV, NULL);
	test_item ("proxy-http-with-auth-import-data", s_vpn, NM_SSH_KEY_PROTO_TCP, "yes");
	test_item ("proxy-http-with-auth-import-data", s_vpn, NM_SSH_KEY_COMP_LZO, NULL);
	test_item ("proxy-http-with-auth-import-data", s_vpn, NM_SSH_KEY_RENEG_SECONDS, "0");
	test_item ("proxy-http-with-auth-import-data", s_vpn, NM_SSH_KEY_REMOTE, "test.server.com");
	test_item ("proxy-http-with-auth-import-data", s_vpn, NM_SSH_KEY_PORT, "443");
	test_item ("proxy-http-with-auth-import-data", s_vpn, NM_SSH_KEY_CERT, NULL);
	test_item ("proxy-http-with-auth-import-data", s_vpn, NM_SSH_KEY_KEY, NULL);
	test_item ("proxy-http-with-auth-import-data", s_vpn, NM_SSH_KEY_STATIC_KEY, NULL);
	test_item ("proxy-http-with-auth-import-data", s_vpn, NM_SSH_KEY_STATIC_KEY_DIRECTION, NULL);
	test_item ("proxy-http-with-auth-import-data", s_vpn, NM_SSH_KEY_TA, NULL);
	test_item ("proxy-http-with-auth-import-data", s_vpn, NM_SSH_KEY_TA_DIR, NULL);
	test_item ("proxy-http-with-auth-import-data", s_vpn, NM_SSH_KEY_CIPHER, "AES-256-CBC");
	test_item ("proxy-http-with-auth-import-data", s_vpn, NM_SSH_KEY_LOCAL_IP, NULL);
	test_item ("proxy-http-with-auth-import-data", s_vpn, NM_SSH_KEY_REMOTE_IP, NULL);
	test_item ("proxy-http-with-auth-import-data", s_vpn, NM_SSH_KEY_AUTH, NULL);
	test_item ("proxy-http-with-auth-import-data", s_vpn, NM_SSH_KEY_AUTH, NULL);
	test_item ("proxy-http-with-auth-import-data", s_vpn, NM_SSH_KEY_PROXY_TYPE, "http");
	test_item ("proxy-http-with-auth-import-data", s_vpn, NM_SSH_KEY_PROXY_SERVER, "proxy.domain.tld");
	test_item ("proxy-http-with-auth-import-data", s_vpn, NM_SSH_KEY_PROXY_PORT, "3128");
	test_item ("proxy-http-with-auth-import-data", s_vpn, NM_SSH_KEY_HTTP_PROXY_USERNAME, "myusername");
	test_secret ("proxy-http-with-auth-import-secrets", s_vpn, NM_SSH_KEY_HTTP_PROXY_PASSWORD, "mypassword");

	g_object_unref (connection);
}

static void
test_proxy_socks_import (NMVpnPluginUiInterface *plugin, const char *dir)
{
	NMConnection *connection;
	NMSettingVPN *s_vpn;

	connection = get_basic_connection ("proxy-socks-import", plugin, dir, "proxy-socks.ovpn");
	ASSERT (connection != NULL, "proxy-socks-import", "failed to import connection");

	/* VPN setting */
	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);
	ASSERT (s_vpn != NULL,
	        "proxy-socks-import", "missing 'vpn' setting");

	/* Data items */
	test_item ("proxy-socks-import-data", s_vpn, NM_SSH_KEY_CONNECTION_TYPE, NM_SSH_CONTYPE_PASSWORD);
	test_item ("proxy-socks-import-data", s_vpn, NM_SSH_KEY_TAP_DEV, NULL);
	test_item ("proxy-socks-import-data", s_vpn, NM_SSH_KEY_PROTO_TCP, "yes");
	test_item ("proxy-socks-import-data", s_vpn, NM_SSH_KEY_COMP_LZO, NULL);
	test_item ("proxy-socks-import-data", s_vpn, NM_SSH_KEY_RENEG_SECONDS, "0");
	test_item ("proxy-socks-import-data", s_vpn, NM_SSH_KEY_REMOTE, "test.server.com");
	test_item ("proxy-socks-import-data", s_vpn, NM_SSH_KEY_PORT, "443");
	test_item ("proxy-socks-import-data", s_vpn, NM_SSH_KEY_CERT, NULL);
	test_item ("proxy-socks-import-data", s_vpn, NM_SSH_KEY_KEY, NULL);
	test_item ("proxy-socks-import-data", s_vpn, NM_SSH_KEY_STATIC_KEY, NULL);
	test_item ("proxy-socks-import-data", s_vpn, NM_SSH_KEY_STATIC_KEY_DIRECTION, NULL);
	test_item ("proxy-socks-import-data", s_vpn, NM_SSH_KEY_TA, NULL);
	test_item ("proxy-socks-import-data", s_vpn, NM_SSH_KEY_TA_DIR, NULL);
	test_item ("proxy-socks-import-data", s_vpn, NM_SSH_KEY_CIPHER, "AES-256-CBC");
	test_item ("proxy-socks-import-data", s_vpn, NM_SSH_KEY_LOCAL_IP, NULL);
	test_item ("proxy-socks-import-data", s_vpn, NM_SSH_KEY_REMOTE_IP, NULL);
	test_item ("proxy-socks-import-data", s_vpn, NM_SSH_KEY_AUTH, NULL);
	test_item ("proxy-socks-import-data", s_vpn, NM_SSH_KEY_AUTH, NULL);
	test_item ("proxy-socks-import-data", s_vpn, NM_SSH_KEY_PROXY_TYPE, "socks");
	test_item ("proxy-socks-import-data", s_vpn, NM_SSH_KEY_PROXY_SERVER, "10.1.1.1");
	test_item ("proxy-socks-import-data", s_vpn, NM_SSH_KEY_PROXY_PORT, "1080");

	g_object_unref (connection);
}

#define PROXY_SOCKS_EXPORTED_NAME "proxy-socks.ovpntest"
static void
test_proxy_socks_export (NMVpnPluginUiInterface *plugin, const char *dir, const char *tmpdir)
{
	NMConnection *connection;
	NMConnection *reimported;
	char *path;
	gboolean success;
	GError *error = NULL;

	connection = get_basic_connection ("proxy-socks-export", plugin, dir, "proxy-socks.ovpn");
	ASSERT (connection != NULL, "proxy-socks-export", "failed to import connection");

	path = g_build_path ("/", tmpdir, PROXY_SOCKS_EXPORTED_NAME, NULL);
	success = nm_vpn_plugin_ui_interface_export (plugin, path, connection, &error);
	if (!success) {
		if (!error)
			FAIL ("proxy-socks-export", "export failed with missing error");
		else
			FAIL ("proxy-socks-export", "export failed: %s", error->message);
	}

	/* Now re-import it and compare the connections to ensure they are the same */
	reimported = get_basic_connection ("proxy-socks-export", plugin, tmpdir, PROXY_SOCKS_EXPORTED_NAME);
	(void) unlink (path);
	ASSERT (reimported != NULL, "proxy-socks-export", "failed to re-import connection");

	/* Clear secrets first, since they don't get exported, and thus would
	 * make the connection comparison below fail.
	 */
	remove_secrets (connection);

	ASSERT (nm_connection_compare (connection, reimported, NM_SETTING_COMPARE_FLAG_EXACT) == TRUE,
	        "proxy-socks-export", "original and reimported connection differ");

	g_object_unref (reimported);
	g_object_unref (connection);
	g_free (path);
}

int main (int argc, char **argv)
{
	GError *error = NULL;
	char *basename;
	NMVpnPluginUiInterface *plugin = NULL;
	char *tmp, *tmp2, *test_dir;

	if (argc != 3)
		FAIL ("args", "usage: %s <conf path> <tmp dir>", argv[0]);

	g_type_init ();
	dbus_g_bus_get (DBUS_BUS_SESSION, NULL);

	if (!nm_utils_init (&error))
		FAIL ("nm-utils-init", "failed to initialize libnm-util: %s", error->message);

	plugin = nm_vpn_plugin_ui_factory (&error);
	if (error)
		FAIL ("plugin-init", "failed to initialize UI plugin: %s", error->message);
	ASSERT (plugin != NULL,
	        "plugin-init", "failed to initialize UI plugin");

	/* Strip off trailing '/' from tests directory if present */
	tmp = argv[1];
	if (tmp[strlen (tmp) - 1] == '/')
		tmp[strlen (tmp) - 1] = '\0';

	if (g_path_is_absolute (tmp))
		test_dir = g_strdup (tmp);
	else {
		tmp2 = g_get_current_dir ();
		test_dir = g_build_filename (tmp2, tmp, NULL);
		g_free (tmp2);
	}

	/* The tests */
	test_password_import (plugin, test_dir);
	test_password_export (plugin, test_dir, argv[2]);

	test_tls_import (plugin, test_dir);
	test_tls_export (plugin, test_dir, argv[2]);

	test_pkcs12_import (plugin, test_dir);
	test_pkcs12_export (plugin, test_dir, argv[2]);

	test_non_utf8_import (plugin, test_dir);

	test_static_key_import (plugin, test_dir);
	test_static_key_export (plugin, test_dir, argv[2]);

	test_port_import (plugin, "port-import", test_dir, "port.ovpn", "port", "2345");
	test_port_export (plugin, "port-export", test_dir, argv[2], "port.ovpn", "port.ovpntest");

	test_port_import (plugin, "rport-import", test_dir, "rport.ovpn", "rport", "6789");
	test_port_export (plugin, "rport-export", test_dir, argv[2], "rport.ovpn", "rport.ovpntest");

	test_tun_opts_import (plugin, test_dir);
	test_tun_opts_export (plugin, test_dir, argv[2]);

	test_proxy_http_import (plugin, test_dir);
	test_proxy_http_export (plugin, test_dir, argv[2]);

	test_proxy_http_with_auth_import (plugin, test_dir);

	test_proxy_socks_import (plugin, test_dir);
	test_proxy_socks_export (plugin, test_dir, argv[2]);

	g_object_unref (plugin);

	basename = g_path_get_basename (argv[0]);
	fprintf (stdout, "%s: SUCCESS\n", basename);
	g_free (basename);
	return 0;
}

