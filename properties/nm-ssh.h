/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * nm-ssh.h : GNOME UI dialogs for configuring ssh VPN connections
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

#ifndef _NM_SSH_H_
#define _NM_SSH_H_

#include <glib-object.h>

typedef enum
{
	SSH_PLUGIN_UI_ERROR_UNKNOWN = 0,
	SSH_PLUGIN_UI_ERROR_INVALID_CONNECTION,
	SSH_PLUGIN_UI_ERROR_INVALID_PROPERTY,
	SSH_PLUGIN_UI_ERROR_MISSING_PROPERTY,
	SSH_PLUGIN_UI_ERROR_FILE_NOT_READABLE,
	SSH_PLUGIN_UI_ERROR_FILE_NOT_SSH
} SshPluginUiError;

#define SSH_TYPE_PLUGIN_UI_ERROR (ssh_plugin_ui_error_get_type ()) 
GType ssh_plugin_ui_error_get_type (void);

#define SSH_PLUGIN_UI_ERROR (ssh_plugin_ui_error_quark ())
GQuark ssh_plugin_ui_error_quark (void);


#define SSH_TYPE_PLUGIN_UI            (ssh_plugin_ui_get_type ())
#define SSH_PLUGIN_UI(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SSH_TYPE_PLUGIN_UI, SshPluginUi))
#define SSH_PLUGIN_UI_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SSH_TYPE_PLUGIN_UI, SshPluginUiClass))
#define SSH_IS_PLUGIN_UI(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SSH_TYPE_PLUGIN_UI))
#define SSH_IS_PLUGIN_UI_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SSH_TYPE_PLUGIN_UI))
#define SSH_PLUGIN_UI_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SSH_TYPE_PLUGIN_UI, SshPluginUiClass))

typedef struct _SshPluginUi SshPluginUi;
typedef struct _SshPluginUiClass SshPluginUiClass;

struct _SshPluginUi {
	GObject parent;
};

struct _SshPluginUiClass {
	GObjectClass parent;
};

GType ssh_plugin_ui_get_type (void);


#define SSH_TYPE_PLUGIN_UI_WIDGET            (ssh_plugin_ui_widget_get_type ())
#define SSH_PLUGIN_UI_WIDGET(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SSH_TYPE_PLUGIN_UI_WIDGET, SshPluginUiWidget))
#define SSH_PLUGIN_UI_WIDGET_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SSH_TYPE_PLUGIN_UI_WIDGET, SshPluginUiWidgetClass))
#define SSH_IS_PLUGIN_UI_WIDGET(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SSH_TYPE_PLUGIN_UI_WIDGET))
#define SSH_IS_PLUGIN_UI_WIDGET_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SSH_TYPE_PLUGIN_UI_WIDGET))
#define SSH_PLUGIN_UI_WIDGET_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SSH_TYPE_PLUGIN_UI_WIDGET, SshPluginUiWidgetClass))

typedef struct _SshPluginUiWidget SshPluginUiWidget;
typedef struct _SshPluginUiWidgetClass SshPluginUiWidgetClass;

struct _SshPluginUiWidget {
	GObject parent;
};

struct _SshPluginUiWidgetClass {
	GObjectClass parent;
};

GType ssh_plugin_ui_widget_get_type (void);

typedef void (*ChangedCallback) (GtkWidget *widget, gpointer user_data);

void init_auth_widget (GtkBuilder *builder,
                       GtkSizeGroup *group,
                       NMSettingVPN *s_vpn,
                       const char *contype,
                       const char *prefix,
                       ChangedCallback changed_cb,
                       gpointer user_data);

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
#define	EXTRA_OPTS_KEY "EXTRA_OPTS"
#define	REMOTE_DEV_KEY "REMOTE_DEV"
#define	DEV_TYPE_KEY "DEV_TYPE"
#define	NO_DEFAULT_ROUTE_KEY "NO_DEFAULT_ROUTE"
#define	TUNNEL_TYPE_KEY "TUNNEL_TYPE"

#endif	/* _NM_SSH_H_ */

