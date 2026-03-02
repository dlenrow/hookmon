#!/bin/bash
set -euo pipefail

echo "==> Installing HookMon server..."

# Create hookmon user
useradd --system --no-create-home --shell /usr/sbin/nologin hookmon || true

# Create directories
mkdir -p /etc/hookmon /var/log/hookmon /var/www/hookmon/dashboard
chown hookmon:hookmon /var/log/hookmon

# Copy server binary (expected to be uploaded by Packer)
# In production, this would be copied from the build output
if [ -f /tmp/hookmon-server ]; then
    cp /tmp/hookmon-server /usr/bin/hookmon-server
    chmod 755 /usr/bin/hookmon-server
fi

# Create systemd service for hookmon-server
cat > /etc/systemd/system/hookmon-server.service <<EOF
[Unit]
Description=HookMon Security Server
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=hookmon
Group=hookmon
ExecStart=/usr/bin/hookmon-server \
    --grpc-addr :9443 \
    --http-addr :8443 \
    --db "postgres://hookmon:hookmon_changeme@localhost:5432/hookmon?sslmode=disable"
Restart=always
RestartSec=5
LimitNOFILE=65536

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/hookmon
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable hookmon-server

echo "==> HookMon server install complete."
