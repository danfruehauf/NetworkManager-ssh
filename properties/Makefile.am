SUBDIRS = .

plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-ssh-properties.la

libnm_ssh_properties_la_SOURCES = \
	nm-ssh.c \
	nm-ssh.h \
	advanced-dialog.c \
	advanced-dialog.h

uidir = $(datadir)/gnome-vpn-properties/ssh
ui_DATA = nm-ssh-dialog.ui

libnm_ssh_properties_la_CFLAGS = \
        $(GTK_CFLAGS) \
        $(NM_CFLAGS) \
        $(GNOMEKEYRING_CFLAGS) \
        $(DISABLE_DEPRECATED) \
        -I$(top_srcdir)/ \
        -DICONDIR=\""$(datadir)/pixmaps"\" \
        -DUIDIR=\""$(uidir)"\" \
        -DG_DISABLE_DEPRECATED \
        -DGDK_DISABLE_DEPRECATED \
        -DGNOME_DISABLE_DEPRECATED \
        -DGNOMELOCALEDIR=\"$(datadir)/locale\" \
        -DVERSION=\"$(VERSION)\"

libnm_ssh_properties_la_LIBADD = \
        $(GTK_LIBS) \
        $(NM_LIBS)

libnm_ssh_properties_la_LDFLAGS = \
        -avoid-version

CLEANFILES = *.bak *~

EXTRA_DIST = \
        $(ui_DATA)
