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
#include <nm-vpn-service-plugin.h>

#include "nm-ssh-service-defines.h"

#define NM_TYPE_SSH_PLUGIN            (nm_ssh_plugin_get_type ())
#define NM_SSH_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SSH_PLUGIN, NMSshPlugin))
#define NM_SSH_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SSH_PLUGIN, NMSshPluginClass))
#define NM_IS_SSH_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SSH_PLUGIN))
#define NM_IS_SSH_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_SSH_PLUGIN))
#define NM_SSH_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SSH_PLUGIN, NMSshPluginClass))

typedef struct {
	NMVpnServicePlugin parent;
} NMSshPlugin;

typedef struct {
	NMVpnServicePluginClass parent;
} NMSshPluginClass;

GType nm_ssh_plugin_get_type (void);

NMSshPlugin *nm_ssh_plugin_new (const char *bus_name);

#endif /* NM_SSH_SERVICE_H */
