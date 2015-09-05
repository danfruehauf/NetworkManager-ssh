SUBDIRS = .

plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-vpn-plugin-ssh.la
if WITH_LIBNM_GLIB
plugin_LTLIBRARIES += libnm-ssh-properties.la
endif

libnm_vpn_plugin_ssh_la_SOURCES = \
	nm-ssh.c \
	nm-ssh.h \
	advanced-dialog.c \
	advanced-dialog.h

libnm_ssh_properties_la_SOURCES = \
        $(libnm_vpn_plugin_ssh_la_SOURCES)

uidir = $(datadir)/gnome-vpn-properties/ssh
ui_DATA = nm-ssh-dialog.ui

common_CFLAGS = \
        $(GTK_CFLAGS) \
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

libnm_vpn_plugin_ssh_la_CFLAGS = \
        $(common_CFLAGS) \
        $(LIBNM_CFLAGS)

libnm_ssh_properties_la_CFLAGS = \
        -DNM_SSH_OLD \
        $(common_CFLAGS) \
        $(LIBNM_GLIB_CFLAGS)

libnm_vpn_plugin_ssh_la_LIBADD = \
        $(GTK_LIBS) \
        $(LIBNM_LIBS)

libnm_ssh_properties_la_LIBADD = \
        $(GTK_LIBS) \
        $(LIBNM_GLIB_LIBS)

libnm_vpn_plugin_ssh_la_LDFLAGS = \
        -avoid-version

libnm_ssh_properties_la_LDFLAGS = \
        $(libnm_vpn_plugin_ssh_la_LDFLAGS)

CLEANFILES = *.bak *~

EXTRA_DIST = \
        $(ui_DATA)
