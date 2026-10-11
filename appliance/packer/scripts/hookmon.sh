#!/bin/bash
# hookmon-server, the dashboard, hookmon-init.sh and the server's systemd
# unit, from the files Packer uploaded to /tmp/hookmon-upload. The same unit
# and database script are what the Ansible appliance role installs.
set -euo pipefail

echo "==> HookMon server..."

UP=/tmp/hookmon-upload

getent group hookmon >/dev/null || groupadd --system hookmon
getent passwd hookmon >/dev/null ||
	useradd --system --gid hookmon --home-dir /nonexistent --no-create-home \
		--shell /usr/sbin/nologin hookmon

install -d -m 0755 /etc/hookmon /var/lib/hookmon /usr/share/hookmon
install -m 0755 "$UP/hookmon-server" /usr/local/bin/hookmon-server
install -m 0755 "$UP/files/hookmon-init.sh" /usr/local/sbin/hookmon-init.sh
install -m 0755 "$UP/files/hookmon-db-setup" /usr/local/sbin/hookmon-db-setup

# The server's default dashboard_dir, and the one hookmon-init.sh writes.
rm -rf /usr/share/hookmon/dashboard
cp -R "$UP/dashboard" /usr/share/hookmon/dashboard
chown -R root:root /usr/share/hookmon/dashboard
find /usr/share/hookmon/dashboard -type d -exec chmod 0755 {} +
find /usr/share/hookmon/dashboard -type f -exec chmod 0644 {} +
test -f /usr/share/hookmon/dashboard/index.html

install -m 0644 "$UP/files/hookmon-server.service" /etc/systemd/system/hookmon-server.service
systemctl daemon-reload
# Enabled now; it starts once hookmon-firstboot has written server.yaml.
systemctl enable hookmon-server.service

/usr/local/bin/hookmon-server --version

echo "==> HookMon server done."
