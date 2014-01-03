Name:           sslscan
Version:        1.10.1
Release:        1%{?dist}
Summary:        Security assessment tool for SSL

Group:          Applications/Internet

#Special exception to allow linking against the OpenSSL libraries
License:        GPLv3+ with exceptions

URL:            https://github.com/DinoTools/sslscan
Source0:        https://github.com/DinoTools/sslscan/archive/%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  openssl-devel
#Requires:       

%description
SSLScan queries SSL services, such as HTTPS, in order to determine the ciphers
that are supported. SSLScan is designed to be easy, lean and fast. 
The output includes preferred ciphers of the SSL service, the certificate
and is in Text and XML formats.

%prep
%setup -q


%build
make %{?_smp_mflags} CFLAGS="$RPM_OPT_FLAGS" LDFLAGS="${LDFLAGS} -lssl -lcrypto"


%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot} BINPATH=%{_bindir}/ MANPATH=%{_mandir}/


%clean
rm -rf %{buildroot}


%files
%defattr(-,root,root,-)
%doc Changelog  README.md  LICENSE  
%attr (755,root,root) %{_bindir}/%{name}
%attr (644,root,root) %{_mandir}/man1/%{name}.1*


%changelog
* Fri Jan 03 2014 Philipp Seidel <phibo at, dinotools.org> 1.10.1
- Build with new Makefile

* Tue Dec 03 2013 Philipp Seidel <phibo at, dinotools.org> 1.10.0
- New release

* Fri Nov 29 2013 Philipp Seidel <phibo at, dinotools.org> 1.9.0
- Build forked version from github

* Wed Apr 07 2010 Michal Ambroz <rebus at, seznam.cz> 1.8.2-3
- build for rawhide requires explicit -lcrypto

* Mon Jan 18 2010 Michal Ambroz <rebus at, seznam.cz> 1.8.2-2
- fix issue with the patch version

* Sat Jan 16 2010 Michal Ambroz <rebus at, seznam.cz> 1.8.2-1
- Initial SPEC for Fedora 12


