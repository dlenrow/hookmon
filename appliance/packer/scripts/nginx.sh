#!/bin/bash
set -euo pipefail

echo "==> Installing nginx for TLS termination..."

export DEBIAN_FRONTEND=noninteractive
apt-get install -y --no-install-recommends nginx

# Generate self-signed cert (replaced during first-boot wizard)
mkdir -p /etc/hookmon/tls
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/hookmon/tls/server.key \
    -out /etc/hookmon/tls/server.crt \
    -subj "/CN=hookmon.local/O=HookMon"

# nginx config
cat > /etc/nginx/sites-available/hookmon <<'EOF'
server {
    listen 443 ssl;
    server_name _;

    ssl_certificate     /etc/hookmon/tls/server.crt;
    ssl_certificate_key /etc/hookmon/tls/server.key;
    ssl_protocols       TLSv1.3;

    # Dashboard static files
    location / {
        root /var/www/hookmon/dashboard;
        try_files $uri $uri/ /index.html;
    }

    # API proxy
    location /api/ {
        proxy_pass http://127.0.0.1:8443;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # WebSocket proxy
    location /api/v1/ws/ {
        proxy_pass http://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}

server {
    listen 80;
    server_name _;
    return 301 https://$host$request_uri;
}
EOF

ln -sf /etc/nginx/sites-available/hookmon /etc/nginx/sites-enabled/hookmon
rm -f /etc/nginx/sites-enabled/default

systemctl restart nginx
systemctl enable nginx

echo "==> nginx setup complete."
