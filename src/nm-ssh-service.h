/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-ssh-service - ssh integration with NetworkManager
 *
 * Copyright (C) 2013 Dan Fruehauf <malkodan@gmail.com>
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

#ifndef NM_SSH_SERVICE_H
#define NM_SSH_SERVICE_H

#include <glib.h>
#include <glib-object.h>
#include <nm-vpn-plugin.h>

#define NM_TYPE_SSH_PLUGIN            (nm_ssh_plugin_get_type ())
#define NM_SSH_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SSH_PLUGIN, NMSshPlugin))
#define NM_SSH_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SSH_PLUGIN, NMSshPluginClass))
#define NM_IS_SSH_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SSH_PLUGIN))
#define NM_IS_SSH_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_SSH_PLUGIN))
#define NM_SSH_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SSH_PLUGIN, NMSshPluginClass))

#define NM_DBUS_SERVICE_SSH    "org.freedesktop.NetworkManager.ssh"
#define NM_DBUS_INTERFACE_SSH  "org.freedesktop.NetworkManager.ssh"
#define NM_DBUS_PATH_SSH       "/org/freedesktop/NetworkManager/ssh"

#define	YES "yes"
#define	NO "no"
#define IS_YES(x) (!strncmp (x, YES, strlen(YES)))

#define	NM_SSH_KEY_REMOTE "remote"
#define	NM_SSH_KEY_REMOTE_IP "remote-ip"
#define	NM_SSH_KEY_LOCAL_IP "local-ip"
#define	NM_SSH_KEY_NETMASK "netmask"
#define	NM_SSH_KEY_PORT "port"
#define	NM_SSH_KEY_TUNNEL_MTU "tunnel-mtu"
#define	NM_SSH_KEY_EXTRA_OPTS "extra-opts"
#define	NM_SSH_KEY_REMOTE_DEV "remote-dev"
#define	NM_SSH_KEY_SSH_AUTH_SOCK "ssh-auth-sock"
#define	NM_SSH_KEY_TAP_DEV "tap-dev"
#define	NM_SSH_KEY_REMOTE_USERNAME "remote-username"
#define	NM_SSH_KEY_NO_DEFAULT_ROUTE "no-default-route"
#define	NM_SSH_KEY_IP_6 "ip-6"
#define	NM_SSH_KEY_REMOTE_IP_6 "remote-ip-6"
#define	NM_SSH_KEY_LOCAL_IP_6 "local-ip-6"
#define	NM_SSH_KEY_NETMASK_6 "netmask-6"
#define	NM_SSH_KEY_AUTH_TYPE "auth-type"
#define	NM_SSH_KEY_KEY_FILE "key-file"
#define	NM_SSH_KEY_PASSWORD "password"

#define	NM_SSH_DEFAULT_PORT 22
#define	NM_SSH_DEFAULT_MTU 1500
#define	NM_SSH_DEFAULT_REMOTE_DEV 100
#define	NM_SSH_DEFAULT_EXTRA_OPTS "-o ServerAliveInterval=10 -o TCPKeepAlive=yes"
#define	NM_SSH_DEFAULT_REMOTE_USERNAME "root"

#define	NM_SSH_AUTH_TYPE_SSH_AGENT "ssh-agent"
#define	NM_SSH_AUTH_TYPE_PASSWORD "password"
#define	NM_SSH_AUTH_TYPE_KEY "key"

#define	NM_SSH_SSH_PASS_ENVIRONMENT_VAR "SSHPASS"

/* Backward compatibility with NetworkManager < 0.9.6 when no IPv6 is supported */
#if !defined(NM_VPN_PLUGIN_CONFIG_EXT_GATEWAY)
#	define NM_VPN_PLUGIN_CONFIG_EXT_GATEWAY NM_VPN_PLUGIN_IP4_CONFIG_EXT_GATEWAY
#endif

#if !defined(NM_VPN_PLUGIN_CONFIG_TUNDEV)
#	define NM_VPN_PLUGIN_CONFIG_TUNDEV NM_VPN_PLUGIN_IP4_CONFIG_TUNDEV
#endif

#if !defined(NM_VPN_PLUGIN_CONFIG_MTU)
#	define NM_VPN_PLUGIN_CONFIG_MTU NM_VPN_PLUGIN_IP4_CONFIG_MTU
#endif
/* End backward compatibility */

typedef struct {
	NMVPNPlugin parent;
} NMSshPlugin;

typedef struct {
	NMVPNPluginClass parent;
} NMSshPluginClass;

GType nm_ssh_plugin_get_type (void);

NMSshPlugin *nm_ssh_plugin_new (void);

#endif /* NM_SSH_SERVICE_H */
