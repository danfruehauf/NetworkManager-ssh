libexec_PROGRAMS = nm-ssh-auth-dialog

nm_ssh_auth_dialog_CPPFLAGS = \
	$(GTK_CFLAGS) \
	$(LIBSECRET_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(LIBNMA_CFLAGS) \
	-I$(top_srcdir)/
	-DICONDIR=\""$(datadir)/pixmaps"\" \
	-DUIDIR=\""$(uidir)"\" \
	-DBINDIR=\""$(bindir)"\" \
	-DG_DISABLE_DEPRECATED \
	-DGDK_DISABLE_DEPRECATED \
	-DGNOME_DISABLE_DEPRECATED \
	-DGNOMELOCALEDIR=\"$(datadir)/locale\" \
	-DVERSION=\"$(VERSION)\"

nm_ssh_auth_dialog_SOURCES = \
	main.c

nm_ssh_auth_dialog_LDADD = \
	$(GTK_LIBS) \
	$(LIBSECRET_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNMA_LIBS)

CLEANFILES = *~
