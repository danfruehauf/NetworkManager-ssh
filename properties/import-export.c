/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
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
 * Copyright (C) 2008 - 2011 Dan Williams <dcbw@redhat.com> and Red Hat, Inc.
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
#include <ctype.h>
#include <stdio.h>

#include <glib/gi18n-lib.h>

#include <nm-setting-vpn.h>
#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>

#include "import-export.h"
#include "nm-ssh.h"
#include "../src/nm-ssh-service.h"
#include "../common/utils.h"

#define AUTH_TAG "auth "
#define AUTH_USER_PASS_TAG "auth-user-pass"
#define CA_TAG "ca "
#define CERT_TAG "cert "
#define CIPHER_TAG "cipher "
#define CLIENT_TAG "client"
#define COMP_TAG "comp-lzo"
#define DEV_TAG "dev "
#define FRAGMENT_TAG "fragment "
#define IFCONFIG_TAG "ifconfig "
#define KEY_TAG "key "
#define MSSFIX_TAG "mssfix"
#define PKCS12_TAG "pkcs12 "
#define PORT_TAG "port "
#define PROTO_TAG "proto "
#define HTTP_PROXY_TAG "http-proxy "
#define HTTP_PROXY_RETRY_TAG "http-proxy-retry"
#define SOCKS_PROXY_TAG "socks-proxy "
#define SOCKS_PROXY_RETRY_TAG "socks-proxy-retry"
#define REMOTE_TAG "remote "
#define RENEG_SEC_TAG "reneg-sec "
#define RPORT_TAG "rport "
#define SECRET_TAG "secret "
#define TLS_AUTH_TAG "tls-auth "
#define TLS_CLIENT_TAG "tls-client"
#define TLS_REMOTE_TAG "tls-remote "
#define TUNMTU_TAG "tun-mtu "


static char *
unquote (const char *line, char **leftover)
{
	char *tmp, *item, *unquoted = NULL, *p;
	gboolean quoted = FALSE;

	if (leftover)
		g_return_val_if_fail (*leftover == NULL, FALSE);

	tmp = g_strdup (line);
	item = g_strstrip (tmp);
	if (!strlen (item)) {
		g_free (tmp);
		return NULL;
	}

	/* Simple unquote */
	if ((item[0] == '"') || (item[0] == '\'')) {
		quoted = TRUE;
		item++;
	}

	/* Unquote stuff using ssh unquoting rules */
	unquoted = g_malloc0 (strlen (item) + 1);
	for (p = unquoted; *item; item++, p++) {
		if (quoted && ((*item == '"') || (*item == '\'')))
			break;
		else if (!quoted && isspace (*item))
			break;

		if (*item == '\\' && *(item+1) == '\\')
			*p = *(++item);
		else if (*item == '\\' && *(item+1) == '"')
			*p = *(++item);
		else if (*item == '\\' && *(item+1) == ' ')
			*p = *(++item);
		else
			*p = *item;
	}
	if (leftover && *item)
		*leftover = g_strdup (item + 1);

	g_free (tmp);
	return unquoted;
}


static gboolean
handle_path_item (const char *line,
                  const char *tag,
                  const char *key,
                  NMSettingVPN *s_vpn,
                  const char *path,
                  char **leftover)
{
	char *file, *full_path = NULL;

	if (strncmp (line, tag, strlen (tag)))
		return FALSE;

	file = unquote (line + strlen (tag), leftover);
	if (!file) {
		if (leftover) {
			g_free (*leftover);
			leftover = NULL;
		}
		return FALSE;
	}

	/* If file isn't an absolute file name, add the default path */
	if (!g_path_is_absolute (file))
		full_path = g_build_filename (path, file, NULL);

	nm_setting_vpn_add_data_item (s_vpn, key, full_path ? full_path : file);

	g_free (file);
	g_free (full_path);
	return TRUE;
}

static char **
get_args (const char *line, int *nitems)
{
	char **split, **sanitized, **tmp, **tmp2;

	split = g_strsplit_set (line, " \t", 0);
	sanitized = g_malloc0 (sizeof (char *) * (g_strv_length (split) + 1));

	for (tmp = split, tmp2 = sanitized; *tmp; tmp++) {
		if (strlen (*tmp))
			*tmp2++ = g_strdup (*tmp);
	}

	g_strfreev (split);
	*nitems = g_strv_length (sanitized);

	return sanitized;
}

static void
handle_direction (const char *tag, const char *key, char *leftover, NMSettingVPN *s_vpn)
{
	glong direction;

	if (!leftover)
		return;

	leftover = g_strstrip (leftover);
	if (!strlen (leftover))
		return;

	errno = 0;
	direction = strtol (leftover, NULL, 10);
	if (errno == 0) {
		if (direction == 0)
			nm_setting_vpn_add_data_item (s_vpn, key, "0");
		else if (direction == 1)
			nm_setting_vpn_add_data_item (s_vpn, key, "1");
	} else
		g_warning ("%s: unknown %s direction '%s'", __func__, tag, leftover);
}

static char *
parse_port (const char *str, const char *line)
{
	glong port;

	errno = 0;
	port = strtol (str, NULL, 10);
	if ((errno == 0) && (port > 0) && (port < 65536))
		return g_strdup_printf ("%d", (gint) port);

	g_warning ("%s: invalid remote port in option '%s'", __func__, line);
	return NULL;
}

static gboolean
parse_http_proxy_auth (const char *path,
                       const char *file,
                       char **out_user,
                       char **out_pass)
{
	char *contents = NULL, *abspath = NULL, *tmp;
	GError *error = NULL;
	char **lines, **iter;

	g_return_val_if_fail (out_user != NULL, FALSE);
	g_return_val_if_fail (out_pass != NULL, FALSE);

	if (!file || !strcmp (file, "stdin") || !strcmp (file, "auto") || !strcmp (file, "'auto'"))
		return TRUE;

	if (!g_path_is_absolute (file)) {
		tmp = g_path_get_dirname (path);
		abspath = g_build_path ("/", tmp, file, NULL);
		g_free (tmp);
	} else
		abspath = g_strdup (file);

	/* Grab user/pass from authfile */
	if (!g_file_get_contents (abspath, &contents, NULL, &error)) {
		g_warning ("%s: unable to read HTTP proxy authfile '%s': (%d) %s",
		           __func__, abspath, error ? error->code : -1,
		           error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
		g_free (abspath);
		return FALSE;
	}

	lines = g_strsplit_set (contents, "\n\r", 0);
	for (iter = lines; iter && *iter; iter++) {
		if (!strlen (*iter))
			continue;
		if (!*out_user)
			*out_user = g_strdup (g_strstrip (*iter));
		else if (!*out_pass) {
			*out_pass = g_strdup (g_strstrip (*iter));
			break;
		}
	}
	if (lines)
		g_strfreev (lines);
	g_free (contents);
	g_free (abspath);

	return *out_user && *out_pass;
}

NMConnection *
do_import (const char *path, char **lines, GError **error)
{
	NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingVPN *s_vpn;
	char *last_dot;
	char **line;
	gboolean have_client = FALSE, have_remote = FALSE;
	gboolean have_pass = FALSE, have_sk = FALSE;
	const char *ctype = NULL;
	char *basename;
	char *default_path, *tmp, *tmp2;
	gboolean http_proxy = FALSE, socks_proxy = FALSE, proxy_set = FALSE;
	int nitems;

	connection = nm_connection_new ();
	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());

	g_object_set (s_vpn, NM_SETTING_VPN_SERVICE_TYPE, NM_DBUS_SERVICE_SSH, NULL);
	
	/* Get the default path for ca, cert, key file, these files maybe
	 * in same path with the configuration file */
	if (g_path_is_absolute (path))
		default_path = g_path_get_dirname (path);
	else {
		tmp = g_get_current_dir ();
		tmp2 = g_path_get_dirname (path);
		default_path = g_build_filename (tmp, tmp2, NULL);
		g_free (tmp);
		g_free (tmp2);
	}

	basename = g_path_get_basename (path);
	last_dot = strrchr (basename, '.');
	if (last_dot)
		*last_dot = '\0';
	g_object_set (s_con, NM_SETTING_CONNECTION_ID, basename, NULL);
	g_free (basename);

	for (line = lines; *line; line++) {
		char *comment, **items = NULL, *leftover = NULL;

		if ((comment = strchr (*line, '#')))
			*comment = '\0';
		if ((comment = strchr (*line, ';')))
			*comment = '\0';
		if (!strlen (*line))
			continue;

		if (   !strncmp (*line, CLIENT_TAG, strlen (CLIENT_TAG))
		    || !strncmp (*line, TLS_CLIENT_TAG, strlen (TLS_CLIENT_TAG))) {
			have_client = TRUE;
			continue;
		}

		if (!strncmp (*line, DEV_TAG, strlen (DEV_TAG))) {
			items = get_args (*line + strlen (DEV_TAG), &nitems);
			if (nitems == 1) {
				if (g_str_has_prefix (items[0], "tun")) {
					/* ignore; default is tun */
				} else if (g_str_has_prefix (items[0], "tap"))
					nm_setting_vpn_add_data_item (s_vpn, NM_SSH_KEY_TAP_DEV, "yes");
				else
					g_warning ("%s: unknown %s option '%s'", __func__, DEV_TAG, *line);
			} else
				g_warning ("%s: invalid number of arguments in option '%s'", __func__, *line);

			g_strfreev (items);
			continue;
		}

		if (!strncmp (*line, PROTO_TAG, strlen (PROTO_TAG))) {
			items = get_args (*line + strlen (PROTO_TAG), &nitems);
			if (nitems == 1) {
				/* Valid parameters are "udp", "tcp-client" and "tcp-server".
				 * 'tcp' isn't technically valid, but it used to be accepted so
				 * we'll handle it here anyway.
				 */
				if (!strcmp (items[0], "udp")) {
					/* ignore; udp is default */
				} else if (   !strcmp (items[0], "tcp-client")
				           || !strcmp (items[0], "tcp-server")
				           || !strcmp (items[0], "tcp")) {
					nm_setting_vpn_add_data_item (s_vpn, NM_SSH_KEY_PROTO_TCP, "yes");
				} else
					g_warning ("%s: unknown %s option '%s'", __func__, PROTO_TAG, *line);
			} else
				g_warning ("%s: invalid number of arguments in option '%s'", __func__, *line);

			g_strfreev (items);
			continue;
		}

		if (!strncmp (*line, MSSFIX_TAG, strlen (MSSFIX_TAG))) {
			nm_setting_vpn_add_data_item (s_vpn, NM_SSH_KEY_MSSFIX, "yes");
			continue;
		}

		if (!strncmp (*line, TUNMTU_TAG, strlen (TUNMTU_TAG))) {
			items = get_args (*line + strlen (TUNMTU_TAG), &nitems);
			if (nitems == 1) {
				glong secs;

				errno = 0;
				secs = strtol (items[0], NULL, 10);
				if ((errno == 0) && (secs >= 0) && (secs < 0xffff)) {
					tmp = g_strdup_printf ("%d", (guint32) secs);
					nm_setting_vpn_add_data_item (s_vpn, NM_SSH_KEY_TUNNEL_MTU, tmp);
					g_free (tmp);
				} else
					g_warning ("%s: invalid size in option '%s'", __func__, *line);
			} else
				g_warning ("%s: invalid number of arguments in option '%s'", __func__, *line);

			g_strfreev (items);
			continue;
		}

		if (!strncmp (*line, FRAGMENT_TAG, strlen (FRAGMENT_TAG))) {
			items = get_args (*line + strlen (FRAGMENT_TAG), &nitems);

			if (nitems == 1) {
				glong secs;

				errno = 0;
				secs = strtol (items[0], NULL, 10);
				if ((errno == 0) && (secs >= 0) && (secs < 0xffff)) {
					tmp = g_strdup_printf ("%d", (guint32) secs);
					nm_setting_vpn_add_data_item (s_vpn, NM_SSH_KEY_FRAGMENT_SIZE, tmp);
					g_free (tmp);
				} else
					g_warning ("%s: invalid size in option '%s'", __func__, *line);
			} else
				g_warning ("%s: invalid number of arguments in option '%s'", __func__, *line);

			g_strfreev (items);
			continue;
		}

		if (!strncmp (*line, COMP_TAG, strlen (COMP_TAG))) {
			nm_setting_vpn_add_data_item (s_vpn, NM_SSH_KEY_COMP_LZO, "yes");
			continue;
		}

		if (!strncmp (*line, RENEG_SEC_TAG, strlen (RENEG_SEC_TAG))) {
			items = get_args (*line + strlen (RENEG_SEC_TAG), &nitems);

			if (nitems == 1) {
				glong secs;

				errno = 0;
				secs = strtol (items[0], NULL, 10);
				if ((errno == 0) && (secs >= 0) && (secs <= 604800)) {
					tmp = g_strdup_printf ("%d", (guint32) secs);
					nm_setting_vpn_add_data_item (s_vpn, NM_SSH_KEY_RENEG_SECONDS, tmp);
					g_free (tmp);
				} else
					g_warning ("%s: invalid time length in option '%s'", __func__, *line);
			}
			g_strfreev (items);
			continue;
		}

		if (   !strncmp (*line, HTTP_PROXY_RETRY_TAG, strlen (HTTP_PROXY_RETRY_TAG))
		    || !strncmp (*line, SOCKS_PROXY_RETRY_TAG, strlen (SOCKS_PROXY_RETRY_TAG))) {
			nm_setting_vpn_add_data_item (s_vpn,
			                              g_strdup (NM_SSH_KEY_PROXY_RETRY),
			                              g_strdup ("yes"));
			continue;
		}

		http_proxy = g_str_has_prefix (*line, HTTP_PROXY_TAG);
		socks_proxy = g_str_has_prefix (*line, SOCKS_PROXY_TAG);
		if ((http_proxy || socks_proxy) && !proxy_set) {
			gboolean success = FALSE;
			const char *proxy_type = NULL;

			if (http_proxy) {
				items = get_args (*line + strlen (HTTP_PROXY_TAG), &nitems);
				proxy_type = "http";
			} else if (socks_proxy) {
				items = get_args (*line + strlen (SOCKS_PROXY_TAG), &nitems);
				proxy_type = "socks";
			}

			if (nitems >= 2) {
				glong port;
				char *s_port = NULL;
				char *user = NULL, *pass = NULL;

				success = TRUE;
				if (http_proxy && nitems >= 3)
					success = parse_http_proxy_auth (path, items[2], &user, &pass);

				if (success) {
					success = FALSE;
					errno = 0;
					port = strtol (items[1], NULL, 10);
					if ((errno == 0) && (port > 0) && (port < 65536)) {
						s_port = g_strdup_printf ("%d", (guint32) port);
						success = TRUE;
					}
				}

				if (success && proxy_type) {
					nm_setting_vpn_add_data_item (s_vpn, NM_SSH_KEY_PROXY_TYPE, proxy_type);

					nm_setting_vpn_add_data_item (s_vpn, NM_SSH_KEY_PROXY_SERVER, items[0]);
					nm_setting_vpn_add_data_item (s_vpn, NM_SSH_KEY_PROXY_PORT, s_port);
					if (user)
						nm_setting_vpn_add_data_item (s_vpn, NM_SSH_KEY_HTTP_PROXY_USERNAME, user);
					if (pass) {
						nm_setting_vpn_add_secret (s_vpn, NM_SSH_KEY_HTTP_PROXY_PASSWORD, pass);
						nm_setting_set_secret_flags (NM_SETTING (s_vpn),
						                             NM_SSH_KEY_HTTP_PROXY_PASSWORD,
						                             NM_SETTING_SECRET_FLAG_AGENT_OWNED,
						                             NULL);
					}
					proxy_set = TRUE;
				}
				g_free (s_port);
				g_free (user);
				g_free (pass);
			}

			if (!success)
				g_warning ("%s: invalid proxy option '%s'", __func__, *line);

			g_strfreev (items);
			continue;
		}

		if (!strncmp (*line, REMOTE_TAG, strlen (REMOTE_TAG))) {
			items = get_args (*line + strlen (REMOTE_TAG), &nitems);
			if (nitems >= 1 && nitems <= 3) {
				nm_setting_vpn_add_data_item (s_vpn, NM_SSH_KEY_REMOTE, items[0]);
				have_remote = TRUE;

				if (nitems >= 2) {
					tmp = parse_port (items[1], *line);
					if (tmp) {
						nm_setting_vpn_add_data_item (s_vpn, NM_SSH_KEY_PORT, tmp);
						g_free (tmp);

						if (nitems == 3) {
							 /* TODO */
						}
					}
				}
			} else
				g_warning ("%s: invalid number of arguments in option '%s'", __func__, *line);

			g_strfreev (items);
			continue;
		}

		if (   !strncmp (*line, PORT_TAG, strlen (PORT_TAG))
		    || !strncmp (*line, RPORT_TAG, strlen (RPORT_TAG))) {
			/* Port specified in 'remote' always takes precedence */
			if (nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_PORT))
				continue;

			if (!strncmp (*line, PORT_TAG, strlen (PORT_TAG)))
				items = get_args (*line + strlen (PORT_TAG), &nitems);
			else if (!strncmp (*line, RPORT_TAG, strlen (RPORT_TAG)))
				items = get_args (*line + strlen (RPORT_TAG), &nitems);
			else
				g_assert_not_reached ();

			if (nitems == 1) {
				tmp = parse_port (items[0], *line);
				if (tmp) {
					nm_setting_vpn_add_data_item (s_vpn, NM_SSH_KEY_PORT, tmp);
					g_free (tmp);
				}
			} else
				g_warning ("%s: invalid number of arguments in option '%s'", __func__, *line);

			g_strfreev (items);
			continue;
		}

		if ( handle_path_item (*line, PKCS12_TAG, NM_SSH_KEY_CA, s_vpn, default_path, NULL) &&
		     handle_path_item (*line, PKCS12_TAG, NM_SSH_KEY_CERT, s_vpn, default_path, NULL) &&
		     handle_path_item (*line, PKCS12_TAG, NM_SSH_KEY_KEY, s_vpn, default_path, NULL))
			continue;

		if (handle_path_item (*line, CA_TAG, NM_SSH_KEY_CA, s_vpn, default_path, NULL))
			continue;

		if (handle_path_item (*line, CERT_TAG, NM_SSH_KEY_CERT, s_vpn, default_path, NULL))
			continue;

		if (handle_path_item (*line, KEY_TAG, NM_SSH_KEY_KEY, s_vpn, default_path, NULL))
			continue;

		if (handle_path_item (*line, SECRET_TAG, NM_SSH_KEY_STATIC_KEY,
		                      s_vpn, default_path, &leftover)) {
			handle_direction ("secret",
			                  NM_SSH_KEY_STATIC_KEY_DIRECTION,
			                  leftover,
			                  s_vpn);
			g_free (leftover);
			have_sk = TRUE;
			continue;
		}

		if (handle_path_item (*line, TLS_AUTH_TAG, NM_SSH_KEY_TA,
		                      s_vpn, default_path, &leftover)) {
			handle_direction ("tls-auth",
			                  NM_SSH_KEY_TA_DIR,
			                  leftover,
			                  s_vpn);
			g_free (leftover);
			continue;
		}

		if (!strncmp (*line, CIPHER_TAG, strlen (CIPHER_TAG))) {
			items = get_args (*line + strlen (CIPHER_TAG), &nitems);
			if (nitems == 1)
				nm_setting_vpn_add_data_item (s_vpn, NM_SSH_KEY_CIPHER, items[0]);
			else
				g_warning ("%s: invalid number of arguments in option '%s'", __func__, *line);

			g_strfreev (items);
			continue;
		}

		if (!strncmp (*line, TLS_REMOTE_TAG, strlen (TLS_REMOTE_TAG))) {
			char *unquoted = unquote (*line + strlen (TLS_REMOTE_TAG), NULL);

			if (unquoted) {
				nm_setting_vpn_add_data_item (s_vpn, NM_SSH_KEY_TLS_REMOTE, unquoted);
				g_free (unquoted);
			} else
				g_warning ("%s: unknown %s option '%s'", __func__, TLS_REMOTE_TAG, *line);

			continue;
		}

		if (!strncmp (*line, IFCONFIG_TAG, strlen (IFCONFIG_TAG))) {
			items = get_args (*line + strlen (IFCONFIG_TAG), &nitems);
			if (nitems == 2) {
				nm_setting_vpn_add_data_item (s_vpn, NM_SSH_KEY_LOCAL_IP, items[0]);
				nm_setting_vpn_add_data_item (s_vpn, NM_SSH_KEY_REMOTE_IP, items[1]);
			} else
				g_warning ("%s: invalid number of arguments in option '%s'", __func__, *line);

			g_strfreev (items);
			continue;
		}

		if (!strncmp (*line, AUTH_USER_PASS_TAG, strlen (AUTH_USER_PASS_TAG))) {
			have_pass = TRUE;
			continue;
		}

		if (!strncmp (*line, AUTH_TAG, strlen (AUTH_TAG))) {
			items = get_args (*line + strlen (AUTH_TAG), &nitems);
			if (nitems == 1)
				nm_setting_vpn_add_data_item (s_vpn, NM_SSH_KEY_AUTH, items[0]);
			else
				g_warning ("%s: invalid number of arguments in option '%s'", __func__, *line);
			g_strfreev (items);
			continue;
		}
	}

	if (!have_client && !have_sk) {
		g_set_error (error,
		             SSH_PLUGIN_UI_ERROR,
		             SSH_PLUGIN_UI_ERROR_FILE_NOT_SSH,
		             "The file to import wasn't a valid SSH client configuration.");
		g_object_unref (connection);
		connection = NULL;
	} else if (!have_remote) {
		g_set_error (error,
		             SSH_PLUGIN_UI_ERROR,
		             SSH_PLUGIN_UI_ERROR_FILE_NOT_SSH,
		             "The file to import wasn't a valid SSH configure (no remote).");
		g_object_unref (connection);
		connection = NULL;
	} else {
		gboolean have_certs = FALSE, have_ca = FALSE;

		if (nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_CA))
			have_ca = TRUE;

		if (   have_ca
		    && nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_CERT)
		    && nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_KEY))
			have_certs = TRUE;

		/* Determine connection type */
		if (have_pass) {
			if (have_certs)
				ctype = NM_SSH_CONTYPE_PASSWORD_TLS;
			else if (have_ca)
				ctype = NM_SSH_CONTYPE_PASSWORD;
		} else if (have_certs) {
			ctype = NM_SSH_CONTYPE_TLS;
		} else if (have_sk)
			ctype = NM_SSH_CONTYPE_STATIC_KEY;

		if (!ctype)
			ctype = NM_SSH_CONTYPE_TLS;

		nm_setting_vpn_add_data_item (s_vpn, NM_SSH_KEY_CONNECTION_TYPE, ctype);

		/* Default secret flags to be agent-owned */
		if (have_pass) {
			nm_setting_set_secret_flags (NM_SETTING (s_vpn),
			                             NM_SSH_KEY_PASSWORD,
			                             NM_SETTING_SECRET_FLAG_AGENT_OWNED,
			                             NULL);
		}
		if (have_certs) {
			const char *key_path;

			key_path = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_KEY);
			if (key_path && is_encrypted (key_path)) {
				/* If there should be a private key password, default it to
				 * being agent-owned.
				 */
				nm_setting_set_secret_flags (NM_SETTING (s_vpn),
				                             NM_SSH_KEY_CERTPASS,
				                             NM_SETTING_SECRET_FLAG_AGENT_OWNED,
				                             NULL);
			}
		}
	}

	g_free (default_path);

	if (connection)
		nm_connection_add_setting (connection, NM_SETTING (s_vpn));
	else if (s_vpn)
		g_object_unref (s_vpn);

	return connection;
}

gboolean
do_export (const char *path, NMConnection *connection, GError **error)
{
	NMSettingConnection *s_con;
	NMSettingVPN *s_vpn;
	FILE *f;
	const char *value;
	const char *gateway = NULL;
	const char *cipher = NULL;
	const char *cacert = NULL;
	const char *connection_type = NULL;
	const char *user_cert = NULL;
	const char *private_key = NULL;
	const char *static_key = NULL;
	const char *static_key_direction = NULL;
	const char *port = NULL;
	const char *local_ip = NULL;
	const char *remote_ip = NULL;
	const char *tls_remote = NULL;
	const char *tls_auth = NULL;
	const char *tls_auth_dir = NULL;
	gboolean success = FALSE;
	gboolean device_tun = TRUE;
	gboolean proto_udp = TRUE;
	gboolean use_lzo = FALSE;
	gboolean reneg_exists = FALSE;
	guint32 reneg = 0;
	const char *proxy_type = NULL;
	const char *proxy_server = NULL;
	const char *proxy_port = NULL;
	const char *proxy_retry = NULL;
	const char *proxy_username = NULL;
	const char *proxy_password = NULL;

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

	value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_CONNECTION_TYPE);
	if (value && strlen (value))
		connection_type = value;

	if (   !strcmp (connection_type, NM_SSH_CONTYPE_TLS)
	    || !strcmp (connection_type, NM_SSH_CONTYPE_PASSWORD)
	    || !strcmp (connection_type, NM_SSH_CONTYPE_PASSWORD_TLS)) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_CA);
		if (value && strlen (value))
			cacert = value;
	}

	if (   !strcmp (connection_type, NM_SSH_CONTYPE_TLS)
	    || !strcmp (connection_type, NM_SSH_CONTYPE_PASSWORD_TLS)) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_CERT);
		if (value && strlen (value))
			user_cert = value;

		value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_KEY);
		if (value && strlen (value))
			private_key = value;
	}

	if (!strcmp (connection_type, NM_SSH_CONTYPE_STATIC_KEY)) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_STATIC_KEY);
		if (value && strlen (value))
			static_key = value;

		value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_STATIC_KEY_DIRECTION);
		if (value && strlen (value))
			static_key_direction = value;
	}

	/* Export tls-remote value now*/
	value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_TLS_REMOTE);
	if (value && strlen (value))
		tls_remote = value;

	/* Advanced values start */
	value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_PORT);
	if (value && strlen (value))
		port = value;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_RENEG_SECONDS);
	if (value && strlen (value)) {
		reneg_exists = TRUE;
		reneg = strtol (value, NULL, 10);
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_PROTO_TCP);
	if (value && !strcmp (value, "yes"))
		proto_udp = FALSE;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_TAP_DEV);
	if (value && !strcmp (value, "yes"))
		device_tun = FALSE;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_COMP_LZO);
	if (value && !strcmp (value, "yes"))
		use_lzo = TRUE;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_CIPHER);
	if (value && strlen (value))
		cipher = value;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_LOCAL_IP);
	if (value && strlen (value))
		local_ip = value;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_REMOTE_IP);
	if (value && strlen (value))
		remote_ip = value;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_TA);
	if (value && strlen (value))
		tls_auth = value;

	value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_TA_DIR);
	if (value && strlen (value))
		tls_auth_dir = value;

	/* Advanced values end */

	fprintf (f, "client\n");
	fprintf (f, "remote %s%s%s\n",
	         gateway,
	         port ? " " : "",
	         port ? port : "");

	/* Handle PKCS#12 (all certs are the same file) */
	if (   cacert && user_cert && private_key
	    && !strcmp (cacert, user_cert) && !strcmp (cacert, private_key))
		fprintf (f, "pkcs12 %s\n", cacert);
	else {
		if (cacert)
			fprintf (f, "ca %s\n", cacert);
		if (user_cert)
			fprintf (f, "cert %s\n", user_cert);
		if (private_key)
			fprintf(f, "key %s\n", private_key);
	}

	if (   !strcmp(connection_type, NM_SSH_CONTYPE_PASSWORD)
	    || !strcmp(connection_type, NM_SSH_CONTYPE_PASSWORD_TLS))
		fprintf (f, "auth-user-pass\n");

	if (!strcmp (connection_type, NM_SSH_CONTYPE_STATIC_KEY)) {
		if (static_key) {
			fprintf (f, "secret %s%s%s\n",
			         static_key,
			         static_key_direction ? " " : "",
			         static_key_direction ? static_key_direction : "");
		} else
			g_warning ("%s: invalid ssh static key configuration (missing static key)", __func__);
	}

	if (reneg_exists)
		fprintf (f, "reneg-sec %d\n", reneg);

	if (cipher)
		fprintf (f, "cipher %s\n", cipher);

	if (use_lzo)
		fprintf (f, "comp-lzo yes\n");

	value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_MSSFIX);
	if (value && strlen (value)) {
		if (!strcmp (value, "yes"))
			fprintf (f, MSSFIX_TAG "\n");
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_TUNNEL_MTU);
	if (value && strlen (value))
		fprintf (f, TUNMTU_TAG " %d\n", (int) strtol (value, NULL, 10));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_FRAGMENT_SIZE);
	if (value && strlen (value))
		fprintf (f, FRAGMENT_TAG " %d\n", (int) strtol (value, NULL, 10));

	fprintf (f, "dev %s\n", device_tun ? "tun" : "tap");
	fprintf (f, "proto %s\n", proto_udp ? "udp" : "tcp");

	if (local_ip && remote_ip)
		fprintf (f, "ifconfig %s %s\n", local_ip, remote_ip);

	if (   !strcmp(connection_type, NM_SSH_CONTYPE_TLS)
	    || !strcmp(connection_type, NM_SSH_CONTYPE_PASSWORD_TLS)) {
		if (tls_remote)
			fprintf (f,"tls-remote \"%s\"\n", tls_remote);

		if (tls_auth) {
			fprintf (f, "tls-auth %s%s%s\n",
			         tls_auth,
			         tls_auth_dir ? " " : "",
			         tls_auth_dir ? tls_auth_dir : "");
		}
	}

	/* Proxy stuff */
	proxy_type = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_PROXY_TYPE);
	if (proxy_type && strlen (proxy_type)) {
		proxy_server = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_PROXY_SERVER);
		proxy_port = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_PROXY_PORT);
		proxy_retry = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_PROXY_RETRY);
		proxy_username = nm_setting_vpn_get_data_item (s_vpn, NM_SSH_KEY_HTTP_PROXY_USERNAME);
		proxy_password = nm_setting_vpn_get_secret (s_vpn, NM_SSH_KEY_HTTP_PROXY_PASSWORD);

		if (!strcmp (proxy_type, "http") && proxy_server && proxy_port) {
			char *authfile, *authcontents, *base, *dirname;

			if (!proxy_port)
				proxy_port = "8080";

			/* If there's a username, need to write an authfile */
			base = g_path_get_basename (path);
			dirname = g_path_get_dirname (path);
			authfile = g_strdup_printf ("%s/%s-httpauthfile", dirname, base);
			g_free (base);
			g_free (dirname);

			fprintf (f, "http-proxy %s %s%s%s\n",
			         proxy_server,
			         proxy_port,
			         proxy_username ? " " : "",
			         proxy_username ? authfile : "");
			if (proxy_retry && !strcmp (proxy_retry, "yes"))
				fprintf (f, "http-proxy-retry\n");

			/* Write out the authfile */
			if (proxy_username) {
				authcontents = g_strdup_printf ("%s\n%s\n",
				                                proxy_username,
				                                proxy_password ? proxy_password : "");
				g_file_set_contents (authfile, authcontents, -1, NULL);
				g_free (authcontents);
			}
			g_free (authfile);
		} else if (!strcmp (proxy_type, "socks") && proxy_server && proxy_port) {
			if (!proxy_port)
				proxy_port = "1080";
			fprintf (f, "socks-proxy %s %s\n", proxy_server, proxy_port);
			if (proxy_retry && !strcmp (proxy_retry, "yes"))
				fprintf (f, "socks-proxy-retry\n");
		}
	}

	/* Add hard-coded stuff */
	fprintf (f,
	         "nobind\n"
	         "auth-nocache\n"
	         "script-security 2\n"
	         "persist-key\n"
	         "persist-tun\n"
	         "user ssh\n"
	         "group ssh\n");
	success = TRUE;

done:
	fclose (f);
	return success;
}

