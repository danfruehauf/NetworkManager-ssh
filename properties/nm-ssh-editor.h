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

#include <gtk/gtk.h>

#if !GTK_CHECK_VERSION(4,0,0)
#define gtk_editable_set_text(editable,text)		gtk_entry_set_text(GTK_ENTRY(editable), (text))
#define gtk_editable_get_text(editable)			gtk_entry_get_text(GTK_ENTRY(editable))
#define gtk_widget_get_root(widget)			gtk_widget_get_toplevel(widget)
#define gtk_check_button_get_active(button)		gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(button))
#define gtk_check_button_set_active(button, active)	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(button), active)
#define gtk_window_destroy(window)			gtk_widget_destroy(GTK_WIDGET (window))
#define gtk_window_set_hide_on_close(window, hide)						\
	G_STMT_START {										\
		G_STATIC_ASSERT(hide);								\
		g_signal_connect_swapped (G_OBJECT (window), "delete-event",			\
					  G_CALLBACK (gtk_widget_hide_on_delete), window);	\
	} G_STMT_END

typedef void GtkRoot;
#endif

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

#endif	/* _NM_SSH_EDITOR_H_ */
