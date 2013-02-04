AM_CPPFLAGS = \
	$(DBUS_CFLAGS) \
	$(NM_CFLAGS) \
	-DG_DISABLE_DEPRECATED \
	-DBINDIR=\"$(bindir)\" \
	-DPREFIX=\""$(prefix)"\" \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DVERSION="\"$(VERSION)\"" \
	-DLIBDIR=\""$(libdir)"\" \
	-DLIBEXECDIR=\""$(libexecdir)"\" \
	-DLOCALSTATEDIR=\""$(localstatedir)"\" \
	-DDATADIR=\"$(datadir)\" \
	-I$(top_srcdir)

libexec_PROGRAMS = nm-ssh-service nm-ssh-service-ssh-helper

nm_ssh_service_SOURCES = \
	nm-ssh-service.c \
	nm-ssh-service.h

nm_ssh_service_LDADD = \
	$(NM_LIBS) \
        $(top_builddir)/common/libnm-ssh-common.la

nm_ssh_service_ssh_helper_SOURCES = \
	nm-ssh-service-ssh-helper.c

nm_ssh_service_ssh_helper_LDADD = \
	$(DBUS_LIBS) \
	$(NM_LIBS)

CLEANFILES = *~
