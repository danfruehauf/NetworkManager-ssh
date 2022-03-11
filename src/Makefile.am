AM_CPPFLAGS = \
	$(LIBNM_CFLAGS) \
	$(GIO_CFLAGS) \
	-DNM_SSH_LOCALEDIR=\"$(datadir)/locale\" \
	-I$(top_srcdir)

libexec_PROGRAMS = nm-ssh-service

nm_ssh_service_SOURCES = \
	nm-ssh-service.c \
	nm-ssh-service.h \
	nm-ssh-service-defines.h

nm_ssh_service_LDADD = \
	$(LIBNM_LIBS) $(GIO_LIBS)

CLEANFILES = *~
