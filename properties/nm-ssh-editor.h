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

#ifndef _NM_SSH_EDITOR_H_
#define _NM_SSH_EDITOR_H_

#include <glib-object.h>

#define SSH_TYPE_EDITOR            (ssh_editor_get_type ())
#define SSH_EDITOR(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SSH_TYPE_EDITOR, SshEditor))
#define SSH_EDITOR_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SSH_TYPE_EDITOR, SshEditorClass))
#define SSH_IS_EDITOR(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SSH_TYPE_EDITOR))
#define SSH_IS_EDITOR_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SSH_TYPE_EDITOR))
#define SSH_EDITOR_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SSH_TYPE_EDITOR, SshEditorClass))

typedef struct _SshEditor SshEditor;
typedef struct _SshEditorClass SshEditorClass;

struct _SshEditor {
	GObject parent;
};

struct _SshEditorClass {
	GObjectClass parent;
};

GType ssh_editor_get_type (void);

NMVpnEditor *nm_ssh_editor_new (NMConnection *connection, GError **error);

typedef void (*ChangedCallback) (GtkWidget *widget, gpointer user_data);

void init_auth_widget (GtkBuilder *builder,
                       GtkSizeGroup *group,
                       NMSettingVpn *s_vpn,
                       const char *contype,
                       const char *prefix,
                       ChangedCallback changed_cb,
                       gpointer user_data);

#endif	/* _NM_SSH_EDITOR_H_ */
