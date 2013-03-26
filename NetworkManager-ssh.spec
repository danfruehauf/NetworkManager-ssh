%global commit ___commit___
%global shortcommit %(c=%{commit}; echo ${c:0:7})
%global checkout ___checkout___%{shortcommit}

Summary: NetworkManager VPN plugin for SSH
Name: NetworkManager-ssh
Version: ___version___
Release: 0.3.%{checkout}%{?dist}
License: GPLv2+
URL: https://github.com/danfruehauf/NetworkManager-ssh
Group: System Environment/Base
Source0: https://github.com/danfruehauf/NetworkManager-ssh/archive/%{commit}/%{name}-%{version}-%{shortcommit}.tar.gz

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
Requires: openssh
Requires: shared-mime-info
Requires: gnome-keyring

%description
This package contains software for integrating VPN capabilites with
the OpenSSH server with NetworkManager and the GNOME desktop.

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
%{_libdir}/NetworkManager/lib*.so*
%{_sysconfdir}/dbus-1/system.d/nm-ssh-service.conf
%{_sysconfdir}/NetworkManager/VPN/nm-ssh-service.name
%{_libexecdir}/nm-ssh-service
%{_libexecdir}/nm-ssh-auth-dialog
%{_datadir}/gnome-vpn-properties/ssh/nm-ssh-dialog.ui
%dir %{_datadir}/gnome-vpn-properties/ssh

%changelog
* Fri Mar 22 2013 Dan Fruehauf <malkodan@gmail.com> - 0.0.3-0.2.20130322git8767415
- Changes to conform with Fedora packaging standards

* Wed Mar 20 2013 Dan Fruehauf <malkodan@gmail.com> - 0.0.3-0.1.20130320gitcf6c00f
- Initial spec release
