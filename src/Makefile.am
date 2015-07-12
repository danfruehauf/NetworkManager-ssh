AM_CPPFLAGS = \
	$(NM_CFLAGS) \
	$(GIO_CFLAGS) \
	-DG_DISABLE_DEPRECATED \
	-DBINDIR=\"$(bindir)\" \
	-DPREFIX=\""$(prefix)"\" \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DVERSION="\"$(VERSION)\"" \
	-DLIBDIR=\""$(libdir)"\" \
	-DLIBEXECDIR=\""$(libexecdir)"\" \
	-DLOCALSTATEDIR=\""$(localstatedir)"\" \
	-DDATADIR=\"$(datadir)\" \
	-DNM_SSH_LOCALEDIR=\"$(datadir)/locale\" \
	-I$(top_srcdir)

libexec_PROGRAMS = nm-ssh-service

nm_ssh_service_SOURCES = \
	nm-ssh-service.c \
	nm-ssh-service.h

nm_ssh_service_LDADD = \
	$(NM_LIBS) $(GIO_LIBS)

CLEANFILES = *~
