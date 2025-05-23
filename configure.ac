AC_PREREQ(2.52)

AC_INIT(NetworkManager-ssh, 1.2.7, malkodan@gmail.com, NetworkManager-ssh)
AM_INIT_AUTOMAKE([1.9 subdir-objects tar-ustar no-dist-gzip dist-xz])
AM_MAINTAINER_MODE

AC_CONFIG_MACRO_DIR([m4])

AC_CONFIG_HEADERS([config.h])

AC_USE_SYSTEM_EXTENSIONS

dnl
dnl Require programs
dnl
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PATH_PROG(GLIB_COMPILE_RESOURCES, glib-compile-resources)

dnl
dnl Required headers
dnl
AC_HEADER_STDC
AC_CHECK_HEADERS(fcntl.h paths.h sys/ioctl.h sys/time.h syslog.h unistd.h)

dnl
dnl Checks for typedefs, structures, and compiler characteristics.
dnl
AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_HEADER_TIME
AC_GNU_SOURCE

dnl
dnl Checks for library functions.
dnl
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MEMCMP
AC_CHECK_FUNCS(select socket uname)

dnl ensure that when the Automake generated makefile calls aclocal,
dnl it honours the $ACLOCAL_FLAGS environment variable
ACLOCAL_AMFLAGS="\${ACLOCAL_FLAGS}"
if test -n "$ac_macro_dir"; then
    ACLOCAL_AMFLAGS="-I $ac_macro_dir $ACLOCAL_AMFLAGS"
fi
AC_SUBST([ACLOCAL_AMFLAGS])

dnl
dnl GNOME support
dnl
AC_ARG_WITH(gnome, AS_HELP_STRING([--without-gnome], [Build NetworkManager-ssh without GNOME support, e.g. vpn service only]))
AM_CONDITIONAL(WITH_GNOME, test x"$with_gnome" != xno)
AC_ARG_WITH(gtk4, AS_HELP_STRING([--with-gtk4], [Build NetworkManager-vpnc with libnma-gtk4 support]), [], [with_gtk4_specified=no])
AM_CONDITIONAL(WITH_GTK4, test x"$with_gtk4" == xyes)
AC_ARG_WITH(libnm-glib, AS_HELP_STRING([--with-libnm-glib], [Build NetworkManager-ssh without libnm-glib comatibility]))
AM_CONDITIONAL(WITH_LIBNM_GLIB, test x"$with_libnm_glib" == xyes)
AC_ARG_ENABLE(absolute-paths, AS_HELP_STRING([--enable-absolute-paths], [Use absolute paths to in .name files. Useful for development. (default is no)]))

GETTEXT_PACKAGE=NetworkManager-ssh
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE,"$GETTEXT_PACKAGE", [Gettext package])

IT_PROG_INTLTOOL([0.35])
AM_GLIB_GNU_GETTEXT

PKG_CHECK_MODULES(GIO, gio-unix-2.0 >= 2.32)
GIO_CFLAGS="$GIO_CFLAGS -DGLIB_VERSION_MIN_REQUIRED=GLIB_VERSION_2_32"
GIO_CFLAGS="$GIO_CFLAGS -DGLIB_VERSION_MAX_ALLOWED=GLIB_VERSION_2_32"
AC_SUBST(GIO_CFLAGS)
AC_SUBST(GIO_LIBS)

if test x"$with_gnome" != xno; then
	PKG_CHECK_MODULES(GTK, gtk+-3.0 >= 3.4)
	GTK_CFLAGS="$GTK_CFLAGS -DGDK_VERSION_MIN_REQUIRED=GDK_VERSION_3_4"
	GTK_CFLAGS="$GTK_CFLAGS -DGDK_VERSION_MAN_REQUIRED=GDK_VERSION_3_4"

	PKG_CHECK_MODULES(LIBNMA, libnma >= 1.1.0)
	PKG_CHECK_MODULES(LIBSECRET, libsecret-1)

	if test x"$with_libnm_glib" == xyes; then
		PKG_CHECK_MODULES(LIBNM_GTK, libnm-gtk >= 1.1.0)
		PKG_CHECK_MODULES(LIBNM_GLIB,
			NetworkManager >= 1.1.0
			libnm-util >= 1.1.0
			libnm-glib >= 1.1.0
			libnm-glib-vpn >= 1.1.0)
		LIBNM_GLIB_CFLAGS="$LIBNM_GLIB_CFLAGS -DNM_VERSION_MIN_REQUIRED=NM_VERSION_1_2"
		LIBNM_GLIB_CFLAGS="$LIBNM_GLIB_CFLAGS -DNM_VERSION_MAX_ALLOWED=NM_VERSION_1_2"
	fi
fi

if test x"$with_gtk4" == xyes; then
	PKG_CHECK_MODULES(GTK4, gtk4 >= 4.0)
	GTK4_CFLAGS="$GTK4_CFLAGS -DGDK_VERSION_MIN_REQUIRED=GDK_VERSION_4_0"
	GTK4_CFLAGS="$GTK4_CFLAGS -DGDK_VERSION_MAX_ALLOWED=GDK_VERSION_4_0"
	PKG_CHECK_MODULES(LIBNMA_GTK4, libnma-gtk4 >= 1.8.33)
fi

PKG_CHECK_MODULES(LIBNM, libnm >= 1.1.0)
LIBNM_CFLAGS="$LIBNM_CFLAGS -DNM_VERSION_MIN_REQUIRED=NM_VERSION_1_2"
LIBNM_CFLAGS="$LIBNM_CFLAGS -DNM_VERSION_MAX_ALLOWED=NM_VERSION_1_2"

NM_VPN_SERVICE_DIR=`$PKG_CONFIG pkg-config --define-variable prefix='\${prefix}' --variable vpnservicedir libnm`
AC_SUBST(NM_VPN_SERVICE_DIR)

NM_COMPILER_WARNINGS

test x"$enable_absolute_paths" = x"yes" && NM_PLUGIN_DIR='$(libdir)/NetworkManager/'
AC_SUBST(NM_PLUGIN_DIR)

dnl
dnl Constants
dnl ip (iproute2) should usually be at /sbin/ip
AC_DEFINE(IFCONFIG, "/sbin/ifconfig", ifconfig)
AC_DEFINE(IPROUTE2, "/sbin/ip", iproute2)
AC_DEFINE(SUDO, "sudo", sudo)

dnl ssh-agent SSH_AUTH_SOCK variable
AC_DEFINE(SSH_AUTH_SOCK, "SSH_AUTH_SOCK", SSH_AUTH_SOCK)

dnl known_hosts default path in home directory
AC_DEFINE(SSH_KNOWN_HOSTS_PATH, ".ssh/known_hosts", SSH_KNOWN_HOSTS_PATH)

dnl
dnl Distribution version string
dnl
AC_ARG_WITH(dist-version, AS_HELP_STRING([--with-dist-version=<dist-version>], [Define the custom version (like distribution package name and revision)]), ac_distver=$withval, ac_distver="")
if ! test x"$ac_distver" = x""; then
  AC_DEFINE_UNQUOTED(DIST_VERSION, "$ac_distver", [Define the distribution version string])
fi

AC_CONFIG_FILES([
Makefile
po/Makefile.in
])
AC_OUTPUT
