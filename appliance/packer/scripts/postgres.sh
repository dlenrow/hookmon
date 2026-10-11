#!/bin/bash
# PostgreSQL 16 (Ubuntu 24.04's own), local connections only. The hookmon
# role, its password and the database are made on first boot
# (hookmon-db-setup), so every appliance has its own password.
set -euo pipefail

echo "==> PostgreSQL 16..."

export DEBIAN_FRONTEND=noninteractive
apt-get -y -q -o DPkg::Lock::Timeout=600 install --no-install-recommends postgresql-16 postgresql-client-16

# Listen on the loopback only. TLS is off: nothing reaches PostgreSQL from
# outside the VM, and hookmon-server connects over localhost. This also
# keeps PostgreSQL from depending on the snakeoil key, which cleanup.sh
# removes so that appliances do not share one.
cat >/etc/postgresql/16/main/conf.d/hookmon.conf <<'EOF'
# HookMon appliance (appliance/packer/scripts/postgres.sh)
listen_addresses = 'localhost'
ssl = off
EOF

systemctl enable postgresql
systemctl restart postgresql

echo "==> PostgreSQL done."
