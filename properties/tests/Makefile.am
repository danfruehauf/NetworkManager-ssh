SUBDIRS = conf

INCLUDES = -I${top_srcdir}

noinst_PROGRAMS = test-import-export

test_import_export_SOURCES = \
	test-import-export.c

test_import_export_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(GTK_CFLAGS) \
	$(GNOMEKEYRING_CFLAGS) \
	$(NM_CFLAGS) \
	$(DBUS_CFLAGS)

test_import_export_LDADD = \
	$(GTHREAD_LIBS) \
	$(GTK_LIBS) \
	$(GNOMEKEYRING_LIBS) \
	$(DBUS_LIBS) \
	$(NM_LIBS) \
	$(top_builddir)/properties/libnm-ssh-properties.la

if WITH_TESTS

check-local: test-import-export
	$(abs_builddir)/test-import-export $(abs_srcdir)/conf $(abs_builddir)/conf

endif

