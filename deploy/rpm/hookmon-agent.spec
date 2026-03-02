Name:           hookmon-agent
Version:        %{version}
Release:        1%{?dist}
Summary:        HookMon Agent - eBPF and LD_PRELOAD security monitor
License:        Apache-2.0
URL:            https://github.com/dlenrow/hookmon

%description
HookMon agent monitors eBPF program loading, LD_PRELOAD injection,
shared memory creation, and dlopen() calls on Linux hosts.
Events are streamed to a central HookMon server for policy
evaluation and alerting.

%install
mkdir -p %{buildroot}/usr/bin
cp %{_sourcedir}/hookmon-agent %{buildroot}/usr/bin/hookmon-agent
mkdir -p %{buildroot}/etc/hookmon
mkdir -p %{buildroot}/var/log/hookmon

%files
/usr/bin/hookmon-agent
%dir /etc/hookmon
%dir /var/log/hookmon

%post
systemctl daemon-reload
systemctl enable hookmon-agent
systemctl start hookmon-agent

%preun
systemctl stop hookmon-agent
systemctl disable hookmon-agent
