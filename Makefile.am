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

RPM_SOURCE_DIR = $(shell rpm --eval '%{_sourcedir}')
RPM_SPEC_DIR = $(shell rpm --eval '%{_specdir}')
PREPARE_SPEC = \
	commit=$(shell git log -n1 --format="%H") && \
	shortcommit=$(shell git log -n1 --format="%H" | cut -c1-7) && \
	checkout=$(shell date --utc "+%Y%m%d"git) && \
	changelog_date="$(shell date --utc "+%a %b %d %Y")" && \
	sed -i \
		-e "s/___version___/$(VERSION)/g" \
		-e "s/___commit___/$$commit/g" \
		-e "s/___checkout___/$$checkout/g" \
		-e "s/___changelog_date___/$$changelog_date/g" \
		-e "s/___shortcommit___/$$shortcommit/g" \
		-e "s/%setup -q -n %{name}-%{commit}/%setup -q -n %{name}-%{version}/g" \
		$(1)

ChangeLog:
	git log --format="* %cd %aN%n- (%h) %s%d%n" --date=local | sed -r 's/[0-9]+:[0-9]+:[0-9]+ //' >> ChangeLog

rpm: ChangeLog dist-gzip
	@set -e; \
	mv $(distdir).tar.gz $(RPM_SOURCE_DIR)/$(PACKAGE)-$(VERSION)-"$$shortcommit".tar.gz && \
	cp $(PACKAGE).spec $(RPM_SPEC_DIR)/$(PACKAGE).spec && \
	sed -i -e "s/%setup -q -n %{name}-%{commit}/%setup -q -n %{name}-%{version}/g" $(RPM_SPEC_DIR)/$(PACKAGE).spec && \
	$(call PREPARE_SPEC, "$(RPM_SPEC_DIR)/$(PACKAGE).spec") && \
	rpmbuild -ba $(RPM_SPEC_DIR)/$(PACKAGE).spec

git-rpm: ChangeLog
	@set -e; \
	wget -P $(RPM_SOURCE_DIR) -c https://github.com/danfruehauf/NetworkManager-ssh/archive/$$commit/NetworkManager-ssh-$(VERSION)-$$shortcommit.tar.gz && \
	wget -P $(RPM_SPEC_DIR) -c https://raw.github.com/danfruehauf/NetworkManager-ssh/$$commit/NetworkManager-ssh.spec && \
	$(call PREPARE_SPEC, "$(RPM_SPEC_DIR)/$(PACKAGE).spec") && \
	rpmbuild -ba $(RPM_SPEC_DIR)/$(PACKAGE).spec

deb: ChangeLog dist-xz
	deb_src_filename=$(PACKAGE:NetworkManager%=network-manager%)_$(VERSION).orig.tar.xz && \
	rm -rf debian/files debian/*.log debian/*.substvars \
		debian/network-manager-ssh-gnome/ debian/network-manager-ssh/ debian/tmp/ && \
	mv $(distdir).tar.xz ../"$$deb_src_filename" && \
	dpkg-buildpackage -B -nc

.PHONY: rpm deb
