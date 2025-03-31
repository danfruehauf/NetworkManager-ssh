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

#ifndef _NM_SSH_EDITOR_PLUGIN_H_
#define _NM_SSH_EDITOR_PLUGIN_H_

#include <glib-object.h>

#define SSH_TYPE_EDITOR_PLUGIN            (ssh_editor_plugin_get_type ())
#define SSH_EDITOR_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SSH_TYPE_EDITOR_PLUGIN, SshEditorPlugin))
#define SSH_EDITOR_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SSH_TYPE_EDITOR_PLUGIN, SshEditorPluginClass))
#define SSH_IS_EDITOR_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SSH_TYPE_EDITOR_PLUGIN))
#define SSH_IS_EDITOR_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SSH_TYPE_EDITOR_PLUGIN))
#define SSH_EDITOR_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SSH_TYPE_EDITOR_PLUGIN, SshEditorPluginClass))

typedef struct _SshEditorPlugin SshEditorPlugin;
typedef struct _SshEditorPluginClass SshEditorPluginClass;

struct _SshEditorPlugin {
	GObject parent;
};

struct _SshEditorPluginClass {
	GObjectClass parent;
};

GType ssh_editor_plugin_get_type (void);

NMVpnEditor *nm_vpn_editor_factory_ssh (NMVpnEditorPlugin *editor_plugin,
                                        NMConnection *connection,
                                        GError **error);

typedef NMVpnEditor *(*NMVpnEditorFactory) (NMVpnEditorPlugin *editor_plugin,
                                            NMConnection *connection,
                                            GError **error);

/* Export/Import key dictionary */
#define	REMOTE_KEY "REMOTE"
#define	AUTH_TYPE_KEY "AUTH_TYPE"
#define	KEY_FILE_KEY "KEY_FILE"
#define	PREFERRED_AUTHENTICATION_KEY "PREFERRED_AUTHENTICATION"
#define	PASSWORD_PROMPT_NR_KEY "PASSWORD_PROMPT_NR"
#define	REMOTE_USERNAME_KEY "REMOTE_USERNAME"
#define	REMOTE_IP_KEY "REMOTE_IP"
#define	LOCAL_IP_KEY "LOCAL_IP"
#define	NETMASK_KEY "NETMASK"
#define	IP_6_KEY "IP_6"
#define	REMOTE_IP_6_KEY "REMOTE_IP_6"
#define	LOCAL_IP_6_KEY "LOCAL_IP_6"
#define	NETMASK_6_KEY "NETMASK_6"
#define	PORT_KEY "PORT"
#define	MTU_KEY "MTU"
#define	REMOTE_DEV_KEY "REMOTE_DEV"
#define	NO_TUNNEL_INTERFACE "NO_TUNNEL_INTERFACE"
#define	SOCKS_BIND_ADDRESS "SOCKS_BIND_ADDRESS"
#define	LOCAL_BIND_ADDRESS "LOCAL_BIND_ADDRESS"
#define	REMOTE_BIND_ADDRESS "REMOTE_BIND_ADDRESS"
#define	DEV_TYPE_KEY "DEV_TYPE"
#define	SUDO_KEY "SUDO"
#define	NO_DEFAULT_ROUTE_KEY "NO_DEFAULT_ROUTE"
#define	TUNNEL_TYPE_KEY "TUNNEL_TYPE"

#endif	/* _NM_SSH_EDITOR_PLUGIN_H_ */

