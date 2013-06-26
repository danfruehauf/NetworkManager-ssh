%global commit ___commit___
%global shortcommit %(c=%{commit}; echo ${c:0:7})
%global checkout ___checkout___%{shortcommit}

Summary:   NetworkManager VPN plugin for SSH
Name:      NetworkManager-ssh
Version:   ___version___
Release:   0.1.%{checkout}%{?dist}
License:   GPLv2+
URL:       https://github.com/danfruehauf/NetworkManager-ssh
Group:     System Environment/Base
Source0:   https://github.com/danfruehauf/NetworkManager-ssh/archive/%{commit}/%{name}-%{version}-%{shortcommit}.tar.gz

BuildRequires: autoconf
BuildRequires: gtk3-devel
BuildRequires: dbus-devel
BuildRequires: NetworkManager-devel
BuildRequires: NetworkManager-glib-devel
BuildRequires: glib2-devel
BuildRequires: libgnome-keyring-devel
BuildRequires: libtool intltool gettext
Requires: gtk3
Requires: dbus
Requires: NetworkManager
Requires: openssh-clients
Requires: shared-mime-info
Requires: gnome-keyring
Requires: sshpass

%global _privatelibs libnm-ssh-properties[.]so.*
%global __provides_exclude ^(%{_privatelibs})$
%global __requires_exclude ^(%{_privatelibs})$

%description
This package contains software for integrating VPN capabilities with
the OpenSSH server with NetworkManager.

%package -n NetworkManager-ssh-gnome
Summary: NetworkManager VPN plugin for SSH - GNOME files
Group: System Environment/Base
Requires: NetworkManager-ssh = %{version}-%{release}
%if 0%{?fedora} > 17
Requires: nm-connection-editor
%else
Requires: NetworkManager-gnome
%endif

%description -n NetworkManager-ssh-gnome
This package contains software for integrating VPN capabilities with
the OpenSSH server with NetworkManager (GNOME files).

%prep
%setup -q -n %{name}-%{commit}

%build
if [ ! -f configure ]; then
  autoreconf -fvi
fi
%configure --disable-static --disable-dependency-tracking --enable-more-warnings=yes --with-gtkver=3
make %{?_smp_mflags}

%install
make DESTDIR=%{buildroot} INSTALL="install -p" CP="cp -p" install

rm -f %{buildroot}%{_libdir}/NetworkManager/lib*.la

%find_lang %{name}

%files -f %{name}.lang
%doc COPYING AUTHORS README ChangeLog
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/nm-ssh-service.conf
%config(noreplace) %{_sysconfdir}/NetworkManager/VPN/nm-ssh-service.name
%{_libexecdir}/nm-ssh-service
%{_libexecdir}/nm-ssh-auth-dialog

%files -n NetworkManager-ssh-gnome
%doc COPYING AUTHORS README ChangeLog
%{_libdir}/NetworkManager/lib*.so*
%dir %{_datadir}/gnome-vpn-properties/ssh
%{_datadir}/gnome-vpn-properties/ssh/nm-ssh-dialog.ui

%changelog
* ___changelog_date___ Dan Fruehauf <malkodan@gmail.com> - 0.0.9-0.1.___checkout______shortcommit___
- Support for password and plain key authentication

* Tue Jun 25 2013 Dan Fruehauf <malkodan@gmail.com> - 0.0.4-0.1.20130625git241fee0
- Can choose to not set VPN as default route

* Fri Apr 19 2013 Dan Fruehauf <malkodan@gmail.com> - 0.0.3-0.8.20130419git3d5321b
- DBUS and NetworkManager files in /etc are no longer config files
- Other refactoring to conform with other NetworkManager VPN plugins

* Fri Apr 19 2013 Dan Fruehauf <malkodan@gmail.com> - 0.0.3-0.8.20130419git3d5321b
- Added sub package for NetworkManager-ssh-gnome

* Tue Apr 02 2013 Dan Fruehauf <malkodan@gmail.com> - 0.0.3-0.6.20130402git6ba59c4
- Fixed dependencies (openssh-clients
- Added private libs

* Sat Mar 30 2013 Dan Fruehauf <malkodan@gmail.com> - 0.0.3-0.5.20130330git9afb20
- Removed macros from changelog

* Thu Mar 28 2013 Dan Fruehauf <malkodan@gmail.com> - 0.0.3-0.4.20130328gita2add30
- Fixed more issues in spec to conform with Fedora Packaging standards

* Tue Mar 26 2013 Dan Fruehauf <malkodan@gmail.com> - 0.0.3-0.3.20130326git7549f1d
- More changes to conform with Fedora packaging standards

* Fri Mar 22 2013 Dan Fruehauf <malkodan@gmail.com> - 0.0.3-0.2.20130322git8767415
- Changes to conform with Fedora packaging standards

* Wed Mar 20 2013 Dan Fruehauf <malkodan@gmail.com> - 0.0.3-0.1.20130320gitcf6c00f
- Initial spec release
