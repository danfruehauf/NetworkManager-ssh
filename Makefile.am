AUTOMAKE_OPTIONS = foreign subdir-objects

SUBDIRS = . po

CLEANFILES =

EXTRA_DIST =

DISTCHECK_CONFIGURE_FLAGS = --with-tests=yes

dbusservicedir = $(sysconfdir)/dbus-1/system.d
dbusservice_DATA = nm-ssh-service.conf

nmvpnservicedir = $(NM_VPN_SERVICE_DIR)
nmvpnservice_DATA = nm-ssh-service.name

libexec_PROGRAMS =

if WITH_LIBNM_GLIB
# Install a file with full path to plugins for an old gnome-shell
# https://bugzilla.gnome.org/show_bug.cgi?id=693590
install-data-hook:
	mkdir -p $(DESTDIR)$(sysconfdir)/NetworkManager/VPN
	sed -e "1s|^|# This file is obsoleted by a file in $(NM_VPN_SERVICE_DIR)\n\n|" \
	    -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|g' \
	    -e 's|[@]PLUGINDIR[@]|$(libdir)/NetworkManager|g' \
	    <$(srcdir)/nm-ssh-service.name.in \
	    >$(DESTDIR)$(sysconfdir)/NetworkManager/VPN/nm-ssh-service.name

uninstall-hook:
	 rm -f $(DESTDIR)$(sysconfdir)/NetworkManager/VPN/nm-ssh-service.name
endif

desktopfile = nm-ssh.desktop.in
iconfile = gnome-mime-application-x-ssh-settings.png

if WITH_GNOME
# FIXME: uncomment when nmce gets --import support
#desktopdir = $(datadir)/applications
#desktop_in_files = $(desktopfile)
#desktop_DATA = $(desktop_in_files:.desktop.in=.desktop)
#@INTLTOOL_DESKTOP_RULE@

#icondir = $(datadir)/icons/hicolor/48x48/apps
#icon_DATA = $(iconfile)
endif

appdatadir = $(datadir)/appdata
appdata_DATA = $(appdata_in_files:.xml.in=.xml)
appdata_in_files = appdata/network-manager-ssh.metainfo.xml.in
@INTLTOOL_XML_RULE@

nm-ssh-service.name: $(srcdir)/nm-ssh-service.name.in
	sed -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|g' \
	    -e 's|[@]PLUGINDIR[@]/|@NM_PLUGIN_DIR@|g' \
	    $< >$@

EXTRA_DIST += nm-ssh-service.name.in \
	$(dbusservice_DATA) \
	$(desktopfile) \
	$(iconfile) \
	$(appdata_in_files) \
	$(appdata_DATA) \
	intltool-extract.in \
	intltool-merge.in \
	intltool-update.in

CLEANFILES += $(nmvpnservice_DATA) \
	$(desktop_DATA) \
	$(appdata_DATA)

DISTCLEANFILES = intltool-extract intltool-merge intltool-update

ACLOCAL_AMFLAGS = -I m4

RPM_SOURCE_DIR = $(shell rpm --eval '%{_sourcedir}')
RPM_SPEC_DIR = $(shell rpm --eval '%{_specdir}')
PREPARE_SPEC = \
	set -e; \
	spec_file=`echo $(1)`; \
	commit=`echo $(2)`; \
	shortcommit=`echo $(3)`; \
	checkout=`date --utc "+%Y%m%d"git`; \
	changelog_date=`date --utc "+%a %b %d %Y"`; \
	sed -i \
		-e "s/___version___/$(VERSION)/g" \
		-e "s/___commit___/$$commit/g" \
		-e "s/___shortcommit___/$$shortcommit/g" \
		-e "s/___checkout___/$$checkout/g" \
		-e "s/___changelog_date___/$$changelog_date/g" \
		$$spec_file

RPMBUILD_AND_VERIFY = \
	set -e; \
	spec_file=`echo $(1)`; \
	tmp_build_log=`mktemp`; \
	rpmbuild -ba $(RPM_SPEC_DIR)/$(PACKAGE).spec | tee $$tmp_build_log; \
	rpms_to_verify=`grep '^Wrote:' $$tmp_build_log | cut -d: -f2 | xargs`; \
	rm -f $$tmp_build_log; \
	rpmlint -iv $$rpms_to_verify

changelog:
	git log --format="* %cd %aN%n- (%h) %s%d%n" --date=local | sed -r 's/[0-9]+:[0-9]+:[0-9]+ //' > ChangeLog

rpm: changelog dist-gzip
	@set -e; \
	commit=`git log -n1 --format="%H"`; \
	shortcommit=`git log -n1 --format="%h"`; \
	mv $(distdir).tar.gz $(RPM_SOURCE_DIR)/$(PACKAGE)-$(VERSION)-$$shortcommit.tar.gz; \
	cp $(PACKAGE).spec $(RPM_SPEC_DIR)/$(PACKAGE).spec; \
	sed -i -e "s/%setup -q -n %{name}-%{commit}/%setup -q -n %{name}-%{version}/g" $(RPM_SPEC_DIR)/$(PACKAGE).spec; \
	$(call PREPARE_SPEC, "$(RPM_SPEC_DIR)/$(PACKAGE).spec", $$commit, $$shortcommit); \
	rpmbuild -ba $(RPM_SPEC_DIR)/$(PACKAGE).spec

git-rpm: changelog
	@set -e; \
	commit=`git log -n1 --format="%H"`; \
	shortcommit=`git log -n1 --format="%h"`; \
	wget -P $(RPM_SOURCE_DIR) \
		-c https://github.com/danfruehauf/NetworkManager-ssh/archive/$$commit/NetworkManager-ssh-$(VERSION)-$$shortcommit.tar.gz; \
	wget -P $(RPM_SPEC_DIR) \
		-c https://raw.github.com/danfruehauf/NetworkManager-ssh/$$commit/NetworkManager-ssh.spec; \
	$(call PREPARE_SPEC, "$(RPM_SPEC_DIR)/$(PACKAGE).spec", $$commit, $$shortcommit); \
	$(call RPMBUILD_AND_VERIFY, "$(RPM_SPEC_DIR)/$(PACKAGE).spec")

deb: changelog dist-xz
	@set -e; \
	deb_src_filename=$(PACKAGE:NetworkManager%=network-manager%)_$(VERSION).orig.tar.xz; \
	rm -rf debian/files debian/*.log debian/*.substvars \
		debian/network-manager-ssh-gnome/ debian/network-manager-ssh/ debian/tmp/; \
	mv $(distdir).tar.xz ../"$$deb_src_filename"; \
	dpkg-buildpackage -B -nc

.PHONY: rpm deb changelog

AM_CPPFLAGS = \
	$(LIBNM_CFLAGS) \
	$(GIO_CFLAGS) \
	-DNM_SSH_LOCALEDIR=\"$(datadir)/locale\" \
	-I$(top_srcdir)

libexec_PROGRAMS += nm-ssh-service

nm_ssh_service_SOURCES = \
	src/nm-ssh-service.c \
	src/nm-ssh-service.h \
	src/nm-ssh-service-defines.h

nm_ssh_service_LDADD = \
	$(LIBNM_LIBS) $(GIO_LIBS)

plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = properties/libnm-vpn-plugin-ssh.la
if WITH_LIBNM_GLIB
plugin_LTLIBRARIES += properties/libnm-ssh-properties.la
endif

properties_libnm_vpn_plugin_ssh_la_SOURCES = \
	properties/nm-ssh.c \
	properties/nm-ssh.h \
	properties/advanced-dialog.c \
	properties/advanced-dialog.h

properties_libnm_ssh_properties_la_SOURCES = \
        $(libnm_vpn_plugin_ssh_la_SOURCES)

uidir = $(datadir)/gnome-vpn-properties/ssh
ui_DATA = properties/nm-ssh-dialog.ui

plugin_CFLAGS = \
        $(GTK_CFLAGS) \
        -I$(top_srcdir)/ \
        -DUIDIR=\""$(uidir)"\"

properties_libnm_vpn_plugin_ssh_la_CFLAGS = \
        $(plugin_CFLAGS) \
        $(LIBNM_CFLAGS)

properties_libnm_ssh_properties_la_CFLAGS = \
        -DNM_SSH_OLD \
        $(plugin_CFLAGS) \
        $(LIBNM_GLIB_CFLAGS)

properties_libnm_vpn_plugin_ssh_la_LIBADD = \
        $(GTK_LIBS) \
        $(LIBNM_LIBS)

properties_libnm_ssh_properties_la_LIBADD = \
        $(GTK_LIBS) \
        $(LIBNM_GLIB_LIBS)

properties_libnm_vpn_plugin_ssh_la_LDFLAGS = \
        -avoid-version

properties_libnm_ssh_properties_la_LDFLAGS = \
        $(libnm_vpn_plugin_ssh_la_LDFLAGS)


EXTRA_DIST += \
        $(ui_DATA)


###################################################################################################
libexec_PROGRAMS += auth_dialog/nm-ssh-auth-dialog

auth_dialog_nm_ssh_auth_dialog_CPPFLAGS = \
	$(GTK_CFLAGS) \
	$(LIBSECRET_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(LIBNMA_CFLAGS) \
	-I$(top_srcdir)/
	-DUIDIR=\""$(uidir)"\"

auth_dialog_nm_ssh_auth_dialog_SOURCES = \
	auth-dialog/main.c

auth_dialog_nm_ssh_auth_dialog_LDADD = \
	$(GTK_LIBS) \
	$(LIBSECRET_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNMA_LIBS)
