#!/bin/bash
# Installs hookmon-firstboot, which runs once on the appliance's first boot:
# hookmon-init.sh --mode host for this VM's hostname and addresses, then the
# database role and password. hookmon-server starts after it.
set -euo pipefail

echo "==> First-boot service..."

UP=/tmp/hookmon-upload/files

install -m 0755 "$UP/hookmon-firstboot" /usr/local/sbin/hookmon-firstboot
install -m 0644 "$UP/hookmon-firstboot.service" /etc/systemd/system/hookmon-firstboot.service

# Make SSH host keys at boot if none exist. cloud-init makes them when the
# platform offers it a datasource; without one, sshd would have no keys.
install -d -m 0755 /etc/systemd/system/ssh.service.d
install -m 0644 "$UP/hookmon-hostkeys.conf" /etc/systemd/system/ssh.service.d/hookmon-hostkeys.conf

systemctl daemon-reload
systemctl enable hookmon-firstboot.service

echo "==> First-boot service done."
