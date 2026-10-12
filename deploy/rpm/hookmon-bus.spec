# hookmon-bus RPM. Built by scripts/build-agent.sh rpm (make package-rpm)
# from prebuilt binaries: the eBPF objects the bus embeds are compiled with
# clang against the build host's kernel BTF, so the binaries are built
# first and packed into Source0 with the unit and the default config.

%global debug_package %{nil}
%global _build_id_links none
# Ship the binaries byte for byte as built and tested: no strip or other
# post-install rewriting.
%global __os_install_post %{nil}
%{!?_unitdir: %global _unitdir /usr/lib/systemd/system}

Name:           hookmon-bus
Version:        %{pkg_version}
Release:        1%{?dist}
Summary:        HookMon sensor bus: detects code entering Linux processes
License:        Apache-2.0
URL:            https://github.com/dlenrow/hookmon
Source0:        hookmon-bus-%{version}.tar.gz
Requires(post):   systemd
Requires(preun):  systemd
Requires(postun): systemd

%description
hookmon-bus runs on each monitored host. Its eight sensors are read-only
and watch the ways code enters a process:
  bpf_syscall     eBPF program loads and attaches (bpf() syscall)
  exec_injection  LD_PRELOAD, LD_AUDIT, LD_LIBRARY_PATH, LD_DEBUG at exec
  shm_monitor     /dev/shm segments of userspace eBPF runtimes (bpftime)
  dlopen_monitor  libraries loaded at run time with dlopen()
  linker_config   changes to /etc/ld.so.preload and ld.so.conf
  ptrace_monitor  ptrace attach and memory or register writes
  lib_integrity   shared libraries changed on disk
  elf_rpath       risky RPATH and RUNPATH in executed binaries

Events stream over mutual TLS to hookmon-server. The hookmon-bus service
starts once an enrollment token is in /etc/hookmon/enroll-token or the
host has enrolled.

%prep
%setup -q

%build
# Nothing to build: see the comment at the top.

%install
install -D -m 0755 hookmon-bus %{buildroot}%{_bindir}/hookmon-bus
install -D -m 0755 hookmon-dlopen-probe %{buildroot}%{_bindir}/hookmon-dlopen-probe
if [ -f hookmon-smoketest ]; then
    install -D -m 0755 hookmon-smoketest %{buildroot}%{_libexecdir}/hookmon/hookmon-smoketest
    install -D -m 0644 libhookmon_smoketest.so %{buildroot}%{_libexecdir}/hookmon/libhookmon_smoketest.so
    install -D -m 0755 hookmon-smoketest-helper %{buildroot}%{_libexecdir}/hookmon/hookmon-smoketest-helper
fi
install -D -m 0644 hookmon-bus.service %{buildroot}%{_unitdir}/hookmon-bus.service
install -D -m 0644 bus.yaml %{buildroot}%{_sysconfdir}/hookmon/bus.yaml
install -d -m 0700 %{buildroot}%{_sharedstatedir}/hookmon
install -d -m 0750 %{buildroot}%{_localstatedir}/log/hookmon

%files
%license LICENSE
%{_bindir}/hookmon-bus
%{_bindir}/hookmon-dlopen-probe
%dir %{_libexecdir}/hookmon
%{_libexecdir}/hookmon/hookmon-smoketest
%{_libexecdir}/hookmon/libhookmon_smoketest.so
%{_libexecdir}/hookmon/hookmon-smoketest-helper
%{_unitdir}/hookmon-bus.service
%dir %{_sysconfdir}/hookmon
%config(noreplace) %{_sysconfdir}/hookmon/bus.yaml
%dir %attr(0700,root,root) %{_sharedstatedir}/hookmon
%dir %attr(0750,root,root) %{_localstatedir}/log/hookmon

# The service is enabled on install but started only when the host is
# configured: /etc/hookmon/enroll-token or /var/lib/hookmon/bus.crt exists
# (the unit's ConditionPathExists lines apply the same rule at boot).
%post
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || :
fi
if [ $1 -eq 1 ]; then
    systemctl enable hookmon-bus.service >/dev/null 2>&1 || :
fi
if [ -e /etc/hookmon/enroll-token ] || [ -e /var/lib/hookmon/bus.crt ]; then
    if [ -d /run/systemd/system ]; then
        systemctl restart hookmon-bus.service || :
    fi
else
    echo "hookmon-bus: installed but not started. Set server_addr in /etc/hookmon/bus.yaml,"
    echo "  copy the server's CA certificate to /etc/hookmon/ca.crt, write the enrollment"
    echo "  token to /etc/hookmon/enroll-token (mode 0600), then: systemctl start hookmon-bus"
fi

%preun
if [ $1 -eq 0 ]; then
    if [ -d /run/systemd/system ]; then
        systemctl stop hookmon-bus.service || :
    fi
    systemctl disable hookmon-bus.service >/dev/null 2>&1 || :
fi

# Erase removes the bus's own files: the token, the CA certificate, the
# enrolled identity and the fallback log. /etc/hookmon and /var/lib/hookmon
# may also hold hookmon-server or hookmon-collector files, so they are
# removed only when empty. An edited bus.yaml is kept as bus.yaml.rpmsave.
%postun
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || :
fi
if [ $1 -eq 0 ]; then
    rm -f /etc/hookmon/enroll-token /etc/hookmon/ca.crt
    for f in bus.key bus.crt ca.crt; do
        rm -f "/var/lib/hookmon/$f" /var/lib/hookmon/."$f".tmp-*
    done
    rm -f /var/log/hookmon/fallback.jsonl
    rmdir /var/lib/hookmon /var/log/hookmon /etc/hookmon 2>/dev/null || :
    if [ -d /run/systemd/system ]; then
        systemctl reset-failed hookmon-bus.service >/dev/null 2>&1 || :
    fi
fi

%changelog
* Sat Oct 10 2026 Dave Lenrow <david.lenrow@illumio.com> - 0.0.0-1
- Ship hookmon-bus and hookmon-dlopen-probe with a systemd unit, a default
  /etc/hookmon/bus.yaml and enrollment through /etc/hookmon/enroll-token.
