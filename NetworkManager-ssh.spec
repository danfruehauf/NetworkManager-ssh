%define nm_version          1:0.9.2
%define dbus_version        1.1
%define gtk2_version        3.0.1
%define openssh_version     6.1
%define shared_mime_version 0.16-3

%define snapshot %{nil}
%define realversion 0.0.1

Summary: NetworkManager VPN plugin for SSH
Name: NetworkManager-ssh
Epoch:   1
Version: 0.0.1
Release: 1%{snapshot}%{?dist}
License: GPLv2+
URL: http://www.gnome.org/projects/NetworkManager/
Group: System Environment/Base
Source: %{name}-%{realversion}%{snapshot}.tar.gz

BuildRequires: gtk3-devel                 >= %{gtk2_version}
BuildRequires: dbus-devel                 >= %{dbus_version}
BuildRequires: NetworkManager-devel       >= %{nm_version}
BuildRequires: NetworkManager-glib-devel  >= %{nm_version}
BuildRequires: glib2-devel
%if 0%{?fedora} > 16
BuildRequires: libgnome-keyring-devel
%else
BuildRequires: gnome-keyring-devel
%endif
BuildRequires: libtool intltool gettext
Requires(post): %{_bindir}/update-desktop-database
Requires(postun): %{_bindir}/update-desktop-database
Requires: gtk3             >= %{gtk2_version}
Requires: dbus             >= %{dbus_version}
Requires: NetworkManager   >= %{nm_version}
Requires: openssh          >= %{openssh_version}
Requires: shared-mime-info >= %{shared_mime_version}
Requires: gnome-keyring

%description
This package contains software for integrating VPN capabilites with
the OpenSSH server with NetworkManager and the GNOME desktop.

%prep
%setup -q -n %{name}-%{realversion}

%build
if [ ! -f configure ]; then
  ./autogen.sh
fi
%configure --disable-static --disable-dependency-tracking --enable-more-warnings=yes --with-gtkver=3
make %{?_smp_mflags}

%install
make install DESTDIR=%{buildroot} INSTALL="%{__install} -p"

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
%defattr(-, root, root)

%doc AUTHORS ChangeLog README
%{_libdir}/NetworkManager/lib*.so*
%{_sysconfdir}/dbus-1/system.d/nm-ssh-service.conf
%{_sysconfdir}/NetworkManager/VPN/nm-ssh-service.name
%{_libexecdir}/nm-ssh-service
%{_datadir}/gnome-vpn-properties/ssh/nm-ssh-dialog.ui
%dir %{_datadir}/gnome-vpn-properties/ssh

%changelog
* Fri Feb 08 2013 Dan Fruehauf - 1:0.0.1.0-1
- Initial version taken from nm-ssh by Dan Williams

