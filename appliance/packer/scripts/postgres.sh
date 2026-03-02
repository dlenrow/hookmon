#!/bin/bash
set -euo pipefail

echo "==> Installing PostgreSQL 16..."

export DEBIAN_FRONTEND=noninteractive

# Install PostgreSQL
apt-get install -y --no-install-recommends postgresql-16

# Configure PostgreSQL to listen only on localhost
sed -i "s/#listen_addresses = 'localhost'/listen_addresses = 'localhost'/" /etc/postgresql/16/main/postgresql.conf

# Create hookmon database and user
sudo -u postgres psql <<EOF
CREATE USER hookmon WITH PASSWORD 'hookmon_changeme';
CREATE DATABASE hookmon OWNER hookmon;
GRANT ALL PRIVILEGES ON DATABASE hookmon TO hookmon;
EOF

# Restart PostgreSQL
systemctl restart postgresql
systemctl enable postgresql

echo "==> PostgreSQL setup complete."
