#!/bin/bash
set -euo pipefail

echo "==> Configuring first-boot setup wizard..."

cat > /usr/local/bin/hookmon-firstboot <<'WIZARD'
#!/bin/bash
set -euo pipefail

echo "============================================"
echo "  HookMon Appliance — First Boot Setup"
echo "============================================"
echo ""

# 1. Admin password
echo "Step 1: Set admin password for HookMon API"
read -sp "Enter admin password: " ADMIN_PASS
echo ""
read -sp "Confirm password: " ADMIN_PASS2
echo ""
if [ "$ADMIN_PASS" != "$ADMIN_PASS2" ]; then
    echo "Passwords do not match. Re-run setup."
    exit 1
fi

# Generate API token from password hash
API_TOKEN=$(echo -n "$ADMIN_PASS" | sha256sum | cut -d' ' -f1)
echo "API Token: $API_TOKEN"
echo "Save this token — you'll need it for CLI and dashboard access."

# 2. TLS certificate
echo ""
echo "Step 2: TLS Certificate"
echo "  1) Keep self-signed certificate"
echo "  2) Provide your own certificate"
read -p "Choice [1]: " TLS_CHOICE
TLS_CHOICE=${TLS_CHOICE:-1}

if [ "$TLS_CHOICE" = "2" ]; then
    read -p "Path to certificate file: " CERT_PATH
    read -p "Path to private key file: " KEY_PATH
    cp "$CERT_PATH" /etc/hookmon/tls/server.crt
    cp "$KEY_PATH" /etc/hookmon/tls/server.key
    systemctl restart nginx
fi

# 3. Generate enrollment token
ENROLL_TOKEN=$(openssl rand -hex 32)
echo ""
echo "Step 3: Agent Enrollment"
echo "Enrollment token: $ENROLL_TOKEN"
echo ""
echo "To enroll agents, run on each host:"
echo "  curl -sSL https://$(hostname):9443/enroll | sudo bash -s -- --token $ENROLL_TOKEN"

# Save config
cat > /etc/hookmon/server-setup.conf <<EOF
api_token=$API_TOKEN
enrollment_token=$ENROLL_TOKEN
setup_complete=true
EOF
chmod 600 /etc/hookmon/server-setup.conf

# Restart server with token
systemctl restart hookmon-server

echo ""
echo "============================================"
echo "  Setup complete! HookMon is running."
echo "  Dashboard: https://$(hostname)"
echo "============================================"

# Disable firstboot
systemctl disable hookmon-firstboot
WIZARD

chmod +x /usr/local/bin/hookmon-firstboot

# Create systemd service for first-boot
cat > /etc/systemd/system/hookmon-firstboot.service <<EOF
[Unit]
Description=HookMon First Boot Setup
After=multi-user.target
ConditionPathExists=!/etc/hookmon/server-setup.conf

[Service]
Type=oneshot
ExecStart=/usr/local/bin/hookmon-firstboot
StandardInput=tty
StandardOutput=tty
TTYPath=/dev/tty1
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable hookmon-firstboot

echo "==> First-boot wizard installed."
