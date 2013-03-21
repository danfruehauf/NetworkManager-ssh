AUTOMAKE_OPTIONS = foreign

SUBDIRS = src

if WITH_GNOME
SUBDIRS += auth-dialog properties po
endif

dbusservicedir = $(sysconfdir)/dbus-1/system.d
dbusservice_DATA = nm-ssh-service.conf

nmvpnservicedir = $(sysconfdir)/NetworkManager/VPN
nmvpnservice_DATA = nm-ssh-service.name

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

nm-ssh-service.name: $(srcdir)/nm-ssh-service.name.in
	sed -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|g' $< >$@

DISTCHECK_CONFIGURE_FLAGS = --with-tests=yes

EXTRA_DIST = nm-ssh-service.name.in \
             $(dbusservice_DATA)  \
             $(desktopfile) \
             $(iconfile) \
             intltool-extract.in  \
             intltool-merge.in    \
             intltool-update.in

CLEANFILES = $(nmvpnservice_DATA) $(desktop_DATA) *~
DISTCLEANFILES = intltool-extract intltool-merge intltool-update

ACLOCAL_AMFLAGS = -I m4

rpm: dist-xz
	@set -e; \
	rpm_source_dir=$(shell rpm --eval '%{_sourcedir}') && \
	rpm_spec_dir=$(shell rpm --eval '%{_specdir}') && \
	commit_tag=$(shell git log -n1 --format="%H") && \
	shortcommit_tag=$(shell git log -n1 --format="%H" | cut -c1-7) && \
	shortcommit_tag2=$(shell echo .`date --utc "+%Y%m%d"`git`git log -n1 --format="%H" | cut -c1-7`) && \
	mv $(distdir).tar.xz "$$rpm_source_dir"/$(PACKAGE)-$(VERSION)-"$$shortcommit_tag".tar.xz && \
	sed -e 's/___version___/$(VERSION)/g' -e "s/___commit___/$$commit_tag/g" $(PACKAGE).spec > $$rpm_spec_dir/$(PACKAGE).spec && \
	git log --format="* %cd %aN%n- (%h) %s%d%n" --date=local | sed -r 's/[0-9]+:[0-9]+:[0-9]+ //' >> $$rpm_spec_dir/$(PACKAGE).spec && \
	rpmbuild -ba $$rpm_spec_dir/$(PACKAGE).spec

deb: dist-xz
	deb_src_filename=$(PACKAGE:NetworkManager%=network-manager%)_$(VERSION).orig.tar.xz && \
	rm -rf debian/files debian/*.log debian/*.substvars \
		debian/network-manager-ssh-gnome/ debian/network-manager-ssh/ debian/tmp/ && \
	mv $(distdir).tar.xz ../"$$deb_src_filename" && \
	dpkg-buildpackage -B -nc

.PHONY: rpm deb
