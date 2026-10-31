# Go already strips the binary; native binutils cannot process a cross-built ELF.
%global debug_package %{nil}
%global __strip /bin/true
%global __objdump /bin/true

Name: securl
Version: %{_securl_version}
Release: %{_securl_release}
Summary: Secure URL requestor for AI agents
License: LicenseRef-Unspecified
URL: https://github.com/LeafAI/securl
Requires: openssh-clients, ca-certificates, systemd, dbus, util-linux, glibc-common

%description
Human-mediated login and an encrypted credential vault for MCP clients.
Includes a per-user systemd daemon, started locked at login, never as root.

%install
mkdir -p "%{buildroot}"
cp -a "%{_securl_payload}/." "%{buildroot}/"

%posttrans
/usr/libexec/securl/user-service restart

%preun
if [ "$1" -eq 0 ]; then
    /usr/libexec/securl/user-service stop
fi

%files
/usr/bin/securl
/usr/lib/systemd/user/securl.service
/usr/lib/systemd/user/default.target.wants/securl.service
%dir /usr/libexec/securl
/usr/libexec/securl/user-service
%dir /usr/share/doc/securl
%doc /usr/share/doc/securl/README.md
%doc /usr/share/doc/securl/THIRD_PARTY_NOTICES.md
