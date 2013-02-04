/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * Dan Williams <dcbw@redhat.com>
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
 * (C) Copyright 2010 Red Hat, Inc.
 */

#include <string.h>
#include <nm-setting-8021x.h>
#include "utils.h"

gboolean
is_pkcs12 (const char *filepath)
{
	NMSetting8021xCKFormat ck_format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
	NMSetting8021x *s_8021x;

	if (!filepath || !strlen (filepath))
		return FALSE;

	if (!g_file_test (filepath, G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR))
		return FALSE;

	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	g_return_val_if_fail (s_8021x != NULL, FALSE);

	nm_setting_802_1x_set_private_key (s_8021x,
	                                   filepath,
	                                   NULL,
	                                   NM_SETTING_802_1X_CK_SCHEME_PATH,
	                                   &ck_format,
	                                   NULL);
	g_object_unref (s_8021x);

	return (ck_format == NM_SETTING_802_1X_CK_FORMAT_PKCS12);
}

#define PROC_TYPE_TAG "Proc-Type: 4,ENCRYPTED"
#define PKCS8_TAG "-----BEGIN ENCRYPTED PRIVATE KEY-----"

/** Checks if a file appears to be an encrypted private key.
 * @param filename the path to the file
 * @return returns true if the key is encrypted, false otherwise
 */
gboolean
is_encrypted (const char *filename)
{
	GIOChannel *pem_chan;
	char *str = NULL;
	gboolean encrypted = FALSE;

	if (!filename || !strlen (filename))
		return FALSE;

	if (is_pkcs12 (filename))
		return TRUE;

	pem_chan = g_io_channel_new_file (filename, "r", NULL);
	if (!pem_chan)
		return FALSE;

	while (g_io_channel_read_line (pem_chan, &str, NULL, NULL, NULL) != G_IO_STATUS_EOF) {
		if (str) {
			if (g_str_has_prefix (str, PROC_TYPE_TAG) || g_str_has_prefix (str, PKCS8_TAG)) {
				encrypted = TRUE;
				break;
			}
			g_free (str);
		}
	}

	g_io_channel_shutdown (pem_chan, FALSE, NULL);
	g_io_channel_unref (pem_chan);
	return encrypted;
}

