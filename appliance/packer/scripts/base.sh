#!/bin/bash
set -euo pipefail

echo "==> Base system hardening..."

export DEBIAN_FRONTEND=noninteractive

# Update system
apt-get update
apt-get upgrade -y

# Install essential packages
apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gnupg \
    ufw \
    unattended-upgrades \
    apt-transport-https

# Enable automatic security updates
cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

# Configure firewall
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp    # SSH (disable after setup in production)
ufw allow 443/tcp   # HTTPS (dashboard)
ufw allow 9443/tcp  # gRPC (agent connections)
ufw --force enable

# Harden SSH
sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config

# Kernel hardening
cat >> /etc/sysctl.d/99-hookmon.conf <<EOF
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
kernel.dmesg_restrict = 1
EOF

echo "==> Base hardening complete."
