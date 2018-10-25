%global commit ___commit___
%global shortcommit %(c=%{commit}; echo ${c:0:7})
%global checkout ___checkout___%{shortcommit}

Summary:   NetworkManager VPN plugin for SSH
Name:      NetworkManager-ssh
Version:   ___version___
Release:   0.9.%{checkout}%{?dist}
License:   GPLv2+
URL:       https://github.com/danfruehauf/NetworkManager-ssh
Group:     System Environment/Base
Source0:   https://github.com/danfruehauf/NetworkManager-ssh/archive/%{commit}/%{name}-%{version}-%{shortcommit}.tar.gz

BuildRequires: autoconf
BuildRequires: gtk3-devel
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
%{_prefix}/lib/NetworkManager/VPN/nm-ssh-service.name

%files -n NetworkManager-ssh-gnome
%doc COPYING AUTHORS README ChangeLog
%{_libdir}/NetworkManager/lib*.so*
%dir %{_datadir}/gnome-vpn-properties/ssh
%{_datadir}/gnome-vpn-properties/ssh/nm-ssh-dialog.ui
%{_datarootdir}/appdata/network-manager-ssh.metainfo.xml

%changelog

