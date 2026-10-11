#!/bin/bash
# Base system: current packages, unattended security updates, firewall,
# SSH and kernel settings.
set -euo pipefail

echo "==> Base system..."

export DEBIAN_FRONTEND=noninteractive
APT=(apt-get -y -q -o DPkg::Lock::Timeout=600 -o Dpkg::Options::=--force-confold)

# cloud-init may still be running its final stage.
cloud-init status --wait >/dev/null || true

"${APT[@]}" update
"${APT[@]}" full-upgrade
"${APT[@]}" install --no-install-recommends ca-certificates openssl ufw unattended-upgrades

# Security updates install themselves.
cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

# Firewall: SSH, and the three hookmon-server listeners. The rules are
# written now and take effect at boot, so the build's SSH session is not
# disturbed.
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH'
ufw allow 8443/tcp comment 'hookmon-server dashboard and REST API'
ufw allow 9443/tcp comment 'hookmon-server bus gRPC (mutual TLS)'
ufw allow 9444/tcp comment 'hookmon-server bus enrollment'
sed -i 's/^ENABLED=.*/ENABLED=yes/' /etc/ufw/ufw.conf

# SSH: keys only, no root login. sshd uses the first value it reads, and
# this file sorts before cloud-init's and the cloud image's.
install -m 0644 /tmp/hookmon-upload/files/10-hookmon.conf /etc/ssh/sshd_config.d/10-hookmon.conf

# Kernel settings.
cat >/etc/sysctl.d/99-hookmon.conf <<'EOF'
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
kernel.dmesg_restrict = 1
EOF

echo "==> Base system done."
