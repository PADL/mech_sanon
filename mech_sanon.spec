Name:		gss-sanon
Version:	0.1
Release:	1%{?dist}
Summary:	Simple Anonymous GSS-API Mechanism
Group:		Security Tools
License:	BSD
URL:		https://github.com/PADL/mech_sanon
Source0:	mech_sanon-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root

BuildRequires:	krb5-devel >= 1.15.1

%description
The Simple Anonymous mechanism (hereafter SAnon) described in this document is
a simple protocol based on the X25519 elliptic curve Diffie–Hellman (ECDH) key
agreement scheme. No authentication of initiator or acceptor is provided. A
potential use of SAnon is to provide a degree of privacy when bootstrapping
unkeyed entities.

%prep
%setup -q -n mech_sanon-%{version}

%build
%configure --with-krb5=%{_prefix}
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
%if 0%{?el6}
install -Dm644 mech $RPM_BUILD_ROOT/%{_sysconfdir}/gss/mech
%else
install -Dm644 mech $RPM_BUILD_ROOT/%{_sysconfdir}/gss/mech.d/gss-sanon.conf
%endif

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{_libdir}/gss/mech_sanon.so
%exclude %{_libdir}/gss/mech_sanon.la
%if 0%{?el6}
%{_sysconfdir}/gss/mech
%else
%{_sysconfdir}/gss/mech.d/gss-sanon.conf
%endif
