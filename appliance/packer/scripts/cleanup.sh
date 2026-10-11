#!/bin/bash
# Last step of the build: remove everything that must differ between
# appliances or that only the build needed. The shutdown command then
# deletes the build user.
set -euo pipefail

echo "==> Cleanup..."

UP=/tmp/hookmon-upload/files

# Network: DHCP on every Ethernet interface, whatever its name or MAC
# address. cloud-init wrote a config matched to the build VM's MAC address;
# replace it, and stop cloud-init from writing another. For a static
# address, edit /etc/netplan/01-hookmon.yaml.
rm -f /etc/netplan/50-cloud-init.yaml
install -m 0600 "$UP/01-hookmon.yaml" /etc/netplan/01-hookmon.yaml
install -m 0644 "$UP/99-hookmon-network.cfg" /etc/cloud/cloud.cfg.d/99-hookmon-network.cfg

rm -rf /tmp/hookmon-upload

export DEBIAN_FRONTEND=noninteractive
apt-get -y -q -o DPkg::Lock::Timeout=600 autoremove --purge
apt-get -y -q clean

# cloud-init runs again on the appliance's first boot, for platforms that
# hand it a datasource (SSH keys, hostname). Its build-time state goes,
# with the password login it turned on for the build.
cloud-init clean --logs --seed
rm -f /etc/ssh/sshd_config.d/50-cloud-init.conf

# Per-machine identity, made again on first boot: SSH host keys (cloud-init
# or the ssh.service drop-in), the snakeoil key (hookmon-firstboot) and the
# machine ID (systemd).
rm -f /etc/ssh/ssh_host_*
rm -f /etc/ssl/private/ssl-cert-snakeoil.key /etc/ssl/certs/ssl-cert-snakeoil.pem
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id
echo hookmon >/etc/hostname

# Logs and history from the build.
journalctl --rotate >/dev/null 2>&1 || true
journalctl --vacuum-time=1s >/dev/null 2>&1 || true
find /var/log -type f \( -name '*.gz' -o -name '*.[0-9]' \) -delete
# --no-create: without it, fs.protected_regular refuses root an O_CREAT open
# of another user's file in a sticky directory such as /var/log/postgresql.
find /var/log -type f -exec truncate --no-create -s 0 {} +
rm -f /root/.bash_history

fstrim -av || true
sync

echo "==> Cleanup done."
