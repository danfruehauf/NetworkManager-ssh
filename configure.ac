AC_PREREQ(2.52)

AC_INIT(NetworkManager-ssh, 0.9.3, malkodan@gmail.com, NetworkManager-ssh)
AM_INIT_AUTOMAKE([1.9 subdir-objects tar-ustar no-dist-gzip dist-bzip2])
AM_MAINTAINER_MODE

AC_CONFIG_MACRO_DIR([m4])

AC_CONFIG_HEADERS([config.h])

dnl
dnl Require programs
dnl
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_LIBTOOL

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

AC_ARG_WITH(ipv6, AS_HELP_STRING([--without-ipv6], [Build NetworkManager-ssh without IPv6 support]))
AM_CONDITIONAL(WITH_IPV6, test x"$with_ipv6" != xno)

GETTEXT_PACKAGE=NetworkManager-ssh
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE,"$GETTEXT_PACKAGE", [Gettext package])

IT_PROG_INTLTOOL([0.35])
AM_GLIB_GNU_GETTEXT

PKG_CHECK_MODULES(GTHREAD, gthread-2.0)
AC_SUBST(GTHREAD_CFLAGS)
AC_SUBST(GTHREAD_LIBS)

PKG_CHECK_MODULES(DBUS, dbus-glib-1 >= 0.74)
AC_SUBST(DBUS_CFLAGS)
AC_SUBST(DBUS_LIBS)

PKG_CHECK_MODULES(GIO, gio-unix-2.0)
AC_SUBST(GIO_CFLAGS)
AC_SUBST(GIO_LIBS)

if test x"$with_gnome" != xno; then
	AC_ARG_WITH([gtkver], AS_HELP_STRING([--with-gtkver], [The major version of GTK+ to build with]),
	            with_gtkver="$withval",with_gtkver=0)

	gtk2_req=2.20
	gtk3_req=2.91.4
	case "${with_gtkver}" in
	       0) PKG_CHECK_MODULES(GTK, gtk+-3.0 > $gtk3_req, ,
	                            [PKG_CHECK_MODULES(GTK, gtk+-2.0 > $gtk2_req)])
		  ;;
	       2) PKG_CHECK_MODULES(GTK, gtk+-2.0 >= $gtk2_req)
	          ;;
	       3) PKG_CHECK_MODULES(GTK, gtk+-3.0 >= $gtk3_req)
	          ;;
	       *) AC_MSG_ERROR(unknown GTK+ version $with_gtkver!)
	          ;;
	esac
	AC_SUBST(GTK_CFLAGS)
	AC_SUBST(GTK_LIBS)

	PKG_CHECK_MODULES(LIBSECRET, libsecret-1)
	AC_SUBST(LIBSECRET_CFLAGS)
	AC_SUBST(LIBSECRET_LIBS)

	dnl maintainer mode stuff
	if test $USE_MAINTAINER_MODE = yes; then
		DISABLE_DEPRECATED="-DG_DISABLE_DEPRECATED -DGCONF_DISABLE_DEPRECATED"
	else
		DISABLE_DEPRECATED=""
	fi
	AC_SUBST(DISABLE_DEPRECATED)
fi

if test x"$with_ipv6" != xno; then
	dnl We need at least NetworkManager 0.9.6 for ipv6 support
	PKG_CHECK_MODULES(NM,
		NetworkManager >= 0.9.6
		libnm-util >= 0.9.6
		libnm-glib >= 0.9.6
		libnm-glib-vpn >= 0.9.6, [], AC_MSG_ERROR([NetworkManager >= 0.9.6 required for IPv6 support. Try with '--without-ipv6']))
	AC_DEFINE(IPV6, "yes", ipv6 support)
else
	PKG_CHECK_MODULES(NM,
		NetworkManager >= 0.8.998
		libnm-util >= 0.8.998
		libnm-glib >= 0.8.998
		libnm-glib-vpn >= 0.8.998)
fi
AC_SUBST(NM_CFLAGS)
AC_SUBST(NM_LIBS)

NM_COMPILER_WARNINGS

dnl
dnl Tests
dnl
AC_ARG_WITH(tests, AS_HELP_STRING([--with-tests], [Build NetworkManager tests]))
AM_CONDITIONAL(WITH_TESTS, test "x$with_tests" = "xyes")
case $with_tests in
    yes)
        with_tests=yes
        ;;
    *)
        with_tests=no
        ;;
esac

dnl
dnl Constants
dnl ifconfig should usually be at /sbin/ifconfig
AC_DEFINE(IFCONFIG, "/sbin/ifconfig", ifconfig)

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
src/Makefile
properties/Makefile
auth-dialog/Makefile
po/Makefile.in
])
AC_OUTPUT
