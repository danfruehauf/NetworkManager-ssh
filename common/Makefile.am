noinst_LTLIBRARIES=libnm-ssh-common.la

libnm_ssh_common_la_CPPFLAGS = \
	$(NM_CFLAGS) \
	-DG_DISABLE_DEPRECATED \
        -I$(top_srcdir)/src/

libnm_ssh_common_la_SOURCES= \
	utils.c \
	utils.h

libnm_ssh_common_la_LIBADD = \
	$(NM_LIBS)

