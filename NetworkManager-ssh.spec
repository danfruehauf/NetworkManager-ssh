%global commit ___commit___
%global shortcommit %(c=%{commit}; echo ${c:0:7})
%global checkout %(date --utc "+%Y%m%d")

Summary: NetworkManager VPN plugin for SSH
Name: NetworkManager-ssh
Version: ___version___
Release: pre1.%{checkout}git%{shortcommit}%{?dist}
License: GPLv2+
URL: https://github.com/danfruehauf/NetworkManager-ssh
Group: System Environment/Base
Source0: https://github.com/danfruehauf/NetworkManager-ssh/archive/%{commit}/%{name}-%{version}-%{shortcommit}.tar.xz

BuildRequires: gtk3-devel
BuildRequires: dbus-devel
BuildRequires: NetworkManager-devel
BuildRequires: NetworkManager-glib-devel
BuildRequires: glib2-devel
BuildRequires: libgnome-keyring-devel
BuildRequires: libtool intltool gettext
Requires(post): %{_bindir}/update-desktop-database
Requires(postun): %{_bindir}/update-desktop-database
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
%setup -q -n %{name}-%{version}

%build
if [ ! -f configure ]; then
  ./autogen.sh
fi
%configure --disable-static --disable-dependency-tracking --enable-more-warnings=yes --with-gtkver=3
make %{?_smp_mflags}

%install
make DESTDIR=%{buildroot} INSTALL="install -p" CP="cp -p" install

rm -f %{buildroot}%{_libdir}/NetworkManager/lib*.la

%find_lang %{name}

%post
/usr/bin/update-desktop-database > /dev/null
touch --no-create %{_datadir}/icons/hicolor
if [ -x /usr/bin/gtk-update-icon-cache ]; then
      /usr/bin/gtk-update-icon-cache --quiet %{_datadir}/icons/hicolor || :
fi

%postun
/usr/bin/update-desktop-database > /dev/null
touch --no-create %{_datadir}/icons/hicolor
if [ -x /usr/bin/gtk-update-icon-cache ]; then
      /usr/bin/gtk-update-icon-cache --quiet %{_datadir}/icons/hicolor || :
fi

%files -f %{name}.lang

%doc COPYING AUTHORS README
%{_libdir}/NetworkManager/lib*.so*
%{_sysconfdir}/dbus-1/system.d/nm-ssh-service.conf
%{_sysconfdir}/NetworkManager/VPN/nm-ssh-service.name
%{_libexecdir}/nm-ssh-service
%{_libexecdir}/nm-ssh-auth-dialog
%{_datadir}/gnome-vpn-properties/ssh/nm-ssh-dialog.ui
%dir %{_datadir}/gnome-vpn-properties/ssh

%changelog
