#!/bin/sh
# hookmon-init.sh: first-run setup for a HookMon appliance.
#
# Makes the CA, the server certificate, the enrollment and API tokens, the
# database (and, for compose, Grafana) passwords, server.yaml and
# collector.yaml. The compose appliance, the Packer image and the Ansible
# appliance role all run this script, so these files are made in one place.
#
# Needs only sh, coreutils and openssl. The hookmon binaries cannot make a
# CA or a server certificate, and openssl is on every host this runs on.
# Run with --help for the options and the files it writes.

set -eu

usage() {
	cat <<'EOF'
Usage: hookmon-init.sh --hostname NAME [options]

Writes a HookMon appliance's certificates, secrets and config files. Safe to
re-run: files that exist are kept, so the CA and the tokens never change
unless --force or --new-enroll-token is given.

Required:
  --hostname NAME       DNS name that sensor buses and browsers use for the
                        server. It is the server certificate's CN and first
                        SAN.

Options:
  --out-dir DIR         where to write the files (default /etc/hookmon)
  --ip ADDR             add an IP address SAN to the server certificate
                        (repeatable)
  --dns NAME            add another DNS SAN (repeatable)
  --mode host|compose   host: the server and collector reach Postgres and
                        Pushgateway on localhost, and server.yaml names files
                        under DIR (Packer, Ansible). compose: they use the
                        service names in deploy/appliance/docker-compose.yml,
                        and server.yaml names files under /etc/hookmon, where
                        the compose file mounts DIR. Default host.
  --token-ttl TTL       enrollment token lifetime, Nh or Nd (default 7d)
  --single-use          the enrollment token enrolls one host only
                        These two apply only when a token is made.
  --grpc-port N         port buses connect to for gRPC (default 9443)
  --enroll-port N       port buses connect to for enrollment (default 9444)
  --https-port N        port for the dashboard and REST API (default 8443)
                        In host mode the server listens on these three. In
                        compose mode the server listens on the defaults in
                        its container and these are the published ports,
                        used only in the printed commands.
  --new-enroll-token    replace the enrollment token (for example after it
                        expires) and rewrite server.yaml. Keeps the CA.
  --force               make a new CA, server certificate, enrollment token
                        and API token, and rewrite server.yaml. Buses enrolled
                        with the old CA must enroll again. The database and
                        Grafana passwords are kept: they are stored in the
                        data volumes on first start.
  -h, --help            show this help

Files (under DIR):
  server.yaml                   0600  hookmon-server config
  collector.yaml                0644  hookmon-collector config
  tls/ca.crt                    0644  CA certificate; copy it to bus hosts
  tls/ca.key                    0600  CA key; signs bus certificates
  tls/server.crt, server.key    0644, 0600
  tls/server.san                0644  the SANs server.crt was issued for
  secrets/enroll-token          0600  enrollment token
  secrets/enroll-token.expires  0600  its expiry (RFC 3339, UTC)
  secrets/enroll-token.single-use 0600 true or false
  secrets/api-token             0600  REST API and dashboard token
  secrets/db-password           0600  Postgres password for user hookmon
  secrets/grafana.env           0600  Grafana admin password (compose mode)
  prometheus/buses.yml          0644  bus scrape targets (compose mode)

The server certificate is issued again, from the same CA, when the SANs
asked for differ from tls/server.san, when it expires within 30 days, or
when it no longer verifies against the CA. server.yaml is rewritten (the old
one kept as server.yaml.bak) only when a secret in it is new, so local
edits such as SIEM connectors survive a re-run. To rewrite server.yaml or
collector.yaml with other options, delete it and run the script again.
EOF
}

die() {
	echo "hookmon-init: $*" >&2
	exit 1
}

note() {
	echo "hookmon-init: $*" >&2
}

# --- options -----------------------------------------------------------------

OUT=/etc/hookmon
NAME=
EXTRA_DNS=
EXTRA_IP=
MODE=host
TTL=7d
SINGLE_USE=false
GRPC_PORT=9443
ENROLL_PORT=9444
HTTPS_PORT=8443
NEW_ENROLL_TOKEN=false
FORCE=false
TOKEN_OPTS=false

need_arg() {
	[ "$2" -ge 2 ] || die "$1 needs a value"
}

valid_dns() {
	case $1 in
	'' | -* | .* | *. | *..* | *[!A-Za-z0-9.-]*) return 1 ;;
	esac
	return 0
}

valid_port() {
	case $1 in
	'' | *[!0-9]*) return 1 ;;
	esac
	[ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

while [ $# -gt 0 ]; do
	case $1 in
	--out-dir) need_arg "$1" $#; OUT=$2; shift 2 ;;
	--hostname) need_arg "$1" $#; NAME=$2; shift 2 ;;
	--ip)
		need_arg "$1" $#
		case $2 in '' | *[!0-9A-Fa-f:.]*) die "--ip $2: not an IP address" ;; esac
		EXTRA_IP="$EXTRA_IP,IP:$2"
		shift 2
		;;
	--dns)
		need_arg "$1" $#
		valid_dns "$2" || die "--dns $2: not a DNS name"
		EXTRA_DNS="$EXTRA_DNS,DNS:$2"
		shift 2
		;;
	--mode) need_arg "$1" $#; MODE=$2; shift 2 ;;
	--token-ttl) need_arg "$1" $#; TTL=$2; TOKEN_OPTS=true; shift 2 ;;
	--single-use) SINGLE_USE=true; TOKEN_OPTS=true; shift ;;
	--grpc-port) need_arg "$1" $#; GRPC_PORT=$2; shift 2 ;;
	--enroll-port) need_arg "$1" $#; ENROLL_PORT=$2; shift 2 ;;
	--https-port) need_arg "$1" $#; HTTPS_PORT=$2; shift 2 ;;
	--new-enroll-token) NEW_ENROLL_TOKEN=true; shift ;;
	--force) FORCE=true; shift ;;
	-h | --help) usage; exit 0 ;;
	*) die "unknown option $1 (see --help)" ;;
	esac
done

[ -n "$NAME" ] || die "--hostname is required (see --help)"
valid_dns "$NAME" || die "--hostname $NAME: not a DNS name"
case $MODE in host | compose) ;; *) die "--mode must be host or compose" ;; esac
for p in "$GRPC_PORT" "$ENROLL_PORT" "$HTTPS_PORT"; do
	valid_port "$p" || die "port $p: want 1-65535"
done

TTL_NUM=${TTL%[hd]}
TTL_UNIT=${TTL#"$TTL_NUM"}
case $TTL_NUM in '' | *[!0-9]*) die "--token-ttl $TTL: want Nh or Nd" ;; esac
case $TTL_UNIT in
h) TTL_SECS=$((TTL_NUM * 3600)) ;;
d) TTL_SECS=$((TTL_NUM * 86400)) ;;
*) die "--token-ttl $TTL: want Nh or Nd" ;;
esac
[ "$TTL_SECS" -gt 0 ] || die "--token-ttl must be more than zero"

# The server certificate's SANs: the hostname, then --dns, then --ip.
SANS="DNS:$NAME$EXTRA_DNS$EXTRA_IP"

command -v openssl >/dev/null 2>&1 || die "openssl not found"
date -u -d @0 +%s >/dev/null 2>&1 || die "date cannot read -d @SECONDS (needs GNU coreutils or busybox)"

# --- helpers -----------------------------------------------------------------

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
trap 'exit 130' INT TERM

# write_file MODE PATH: write stdin to PATH through a temporary file in the
# same directory, so PATH is never seen half-written or with the wrong mode.
write_file() {
	wf_tmp=$(mktemp "$2.XXXXXX")
	cat >"$wf_tmp"
	chmod "$1" "$wf_tmp"
	mv -f "$wf_tmp" "$2"
}

# quiet CMD...: run CMD, showing its output only if it fails.
quiet() {
	if ! "$@" >"$WORK/output" 2>&1; then
		cat "$WORK/output" >&2
		die "failed: $*"
	fi
}

# install_file MODE SRC DEST: move a file made in $WORK into place.
install_file() {
	if_tmp=$(mktemp "$3.XXXXXX")
	cat "$2" >"$if_tmp"
	chmod "$1" "$if_tmp"
	mv -f "$if_tmp" "$3"
}

backup() {
	if [ -e "$1" ]; then
		cp -p "$1" "$1.bak"
		note "kept the previous $(basename "$1") as $1.bak"
	fi
}

rand_hex() {
	openssl rand -hex "$1"
}

new_key() {
	quiet openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1"
}

# same_key KEY CERT: the private key belongs to the certificate.
same_key() {
	[ "$(openssl pkey -in "$1" -pubout 2>/dev/null)" = "$(openssl x509 -in "$2" -noout -pubkey 2>/dev/null)" ]
}

CREATED=
KEPT=
created() { CREATED="$CREATED, $1"; }
kept() { KEPT="$KEPT, $1"; }

# --- directories -------------------------------------------------------------

umask 077
[ -d "$OUT" ] || (umask 022 && mkdir -p "$OUT")
OUT=$(cd "$OUT" && pwd -P)
mkdir -p "$OUT/tls" "$OUT/secrets"
chmod 0755 "$OUT/tls"
chmod 0700 "$OUT/secrets"
if [ "$MODE" = compose ]; then
	mkdir -p "$OUT/prometheus"
	chmod 0755 "$OUT/prometheus"
fi

TLS=$OUT/tls
SEC=$OUT/secrets

# Paths as the server sees them: the compose file mounts DIR at /etc/hookmon.
if [ "$MODE" = compose ]; then
	CFG_PATH=/etc/hookmon
	DB_HOST=postgres
	PUSHGATEWAY=http://pushgateway:9091
	LISTEN_GRPC=:9443
	LISTEN_ENROLL=:9444
	LISTEN_HTTPS=:8443
else
	CFG_PATH=$OUT
	DB_HOST=localhost
	PUSHGATEWAY=http://localhost:9091
	LISTEN_GRPC=:$GRPC_PORT
	LISTEN_ENROLL=:$ENROLL_PORT
	LISTEN_HTTPS=:$HTTPS_PORT
fi

# A config written for the other mode would point at the wrong hosts.
check_mode() {
	if [ -e "$1" ] && head -n 1 "$1" | grep -q '^# Written by hookmon-init.sh (mode: ' &&
		! head -n 1 "$1" | grep -q "^# Written by hookmon-init.sh (mode: $MODE)"; then
		die "$1 was written for another --mode; delete it to write it for --mode $MODE"
	fi
}
check_mode "$OUT/collector.yaml"
if [ "$FORCE" = false ] && [ "$NEW_ENROLL_TOKEN" = false ]; then
	check_mode "$OUT/server.yaml"
fi

# --- CA ----------------------------------------------------------------------

NEW_CA=false
if [ "$FORCE" = true ] || { [ ! -e "$TLS/ca.crt" ] && [ ! -e "$TLS/ca.key" ]; }; then
	new_key "$WORK/ca.key"
	cat >"$WORK/ca.cnf" <<EOF
[req]
distinguished_name = dn
prompt = no
x509_extensions = v3_ca
[dn]
O = HookMon
CN = HookMon CA $NAME $(rand_hex 4)
[v3_ca]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF
	quiet openssl req -new -x509 -config "$WORK/ca.cnf" -key "$WORK/ca.key" \
		-sha256 -days 3650 -out "$WORK/ca.crt"
	install_file 0600 "$WORK/ca.key" "$TLS/ca.key"
	install_file 0644 "$WORK/ca.crt" "$TLS/ca.crt"
	NEW_CA=true
	created CA
else
	if [ ! -s "$TLS/ca.crt" ] || [ ! -s "$TLS/ca.key" ]; then
		die "found only one of $TLS/ca.crt and $TLS/ca.key; restore the other, or use --force for a new CA"
	fi
	same_key "$TLS/ca.key" "$TLS/ca.crt" || die "$TLS/ca.key does not belong to $TLS/ca.crt"
	openssl x509 -checkend 0 -noout -in "$TLS/ca.crt" >/dev/null ||
		die "the CA in $TLS/ca.crt has expired; use --force for a new one"
	chmod 0600 "$TLS/ca.key"
	chmod 0644 "$TLS/ca.crt"
	kept CA
fi

# --- server certificate -------------------------------------------------------

server_cert_reason() {
	if [ "$NEW_CA" = true ]; then
		echo "new CA"
	elif [ ! -s "$TLS/server.crt" ] || [ ! -s "$TLS/server.key" ]; then
		echo "missing"
	elif [ ! -s "$TLS/server.san" ] || [ "$(cat "$TLS/server.san")" != "$SANS" ]; then
		echo "SANs changed to $SANS"
	elif ! openssl x509 -checkend 2592000 -noout -in "$TLS/server.crt" >/dev/null; then
		echo "expires within 30 days"
	elif ! openssl verify -purpose sslserver -CAfile "$TLS/ca.crt" "$TLS/server.crt" >/dev/null 2>&1; then
		echo "does not verify against the CA"
	elif ! same_key "$TLS/server.key" "$TLS/server.crt"; then
		echo "key does not match"
	fi
}

REASON=$(server_cert_reason)
if [ -n "$REASON" ]; then
	new_key "$WORK/server.key"
	cat >"$WORK/server.cnf" <<EOF
[req]
distinguished_name = dn
prompt = no
[dn]
CN = $NAME
[v3_server]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = $SANS
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF
	quiet openssl req -new -config "$WORK/server.cnf" -key "$WORK/server.key" -out "$WORK/server.csr"
	quiet openssl x509 -req -in "$WORK/server.csr" -CA "$TLS/ca.crt" -CAkey "$TLS/ca.key" \
		-set_serial "0x$(rand_hex 16)" -sha256 -days 825 \
		-extfile "$WORK/server.cnf" -extensions v3_server -out "$WORK/server.crt"
	quiet openssl verify -purpose sslserver -CAfile "$TLS/ca.crt" "$WORK/server.crt"
	install_file 0600 "$WORK/server.key" "$TLS/server.key"
	install_file 0644 "$WORK/server.crt" "$TLS/server.crt"
	printf '%s\n' "$SANS" | write_file 0644 "$TLS/server.san"
	created "server certificate ($REASON)"
else
	chmod 0600 "$TLS/server.key"
	chmod 0644 "$TLS/server.crt"
	kept "server certificate"
fi

# --- secrets ------------------------------------------------------------------

SERVER_CHANGED=false

if [ "$FORCE" = true ] || [ "$NEW_ENROLL_TOKEN" = true ] || [ ! -s "$SEC/enroll-token" ]; then
	rand_hex 32 | write_file 0600 "$SEC/enroll-token"
	date -u -d "@$(($(date -u +%s) + TTL_SECS))" +%Y-%m-%dT%H:%M:%SZ |
		write_file 0600 "$SEC/enroll-token.expires"
	printf '%s\n' "$SINGLE_USE" | write_file 0600 "$SEC/enroll-token.single-use"
	SERVER_CHANGED=true
	created "enrollment token"
else
	[ -s "$SEC/enroll-token.expires" ] ||
		die "$SEC/enroll-token.expires is missing; use --new-enroll-token"
	if [ "$TOKEN_OPTS" = true ]; then
		note "kept the existing enrollment token; --token-ttl and --single-use apply only to a new one (--new-enroll-token)"
	fi
	kept "enrollment token"
fi

if [ "$FORCE" = true ] || [ ! -s "$SEC/api-token" ]; then
	rand_hex 32 | write_file 0600 "$SEC/api-token"
	SERVER_CHANGED=true
	created "API token"
else
	kept "API token"
fi

# Not replaced by --force: Postgres stores it in its volume on first start.
if [ ! -s "$SEC/db-password" ]; then
	rand_hex 24 | write_file 0600 "$SEC/db-password"
	SERVER_CHANGED=true
	created "database password"
else
	kept "database password"
fi

if [ "$MODE" = compose ]; then
	# Not replaced by --force: Grafana stores it in its volume on first start.
	if [ ! -s "$SEC/grafana.env" ]; then
		printf 'GF_SECURITY_ADMIN_PASSWORD=%s\n' "$(rand_hex 16)" | write_file 0600 "$SEC/grafana.env"
		created "Grafana admin password"
	else
		kept "Grafana admin password"
	fi
fi

for f in "$SEC"/*; do
	[ -f "$f" ] && chmod 0600 "$f"
done

ENROLL_TOKEN=$(cat "$SEC/enroll-token")
ENROLL_EXPIRES=$(cat "$SEC/enroll-token.expires")
ENROLL_SINGLE_USE=$(cat "$SEC/enroll-token.single-use" 2>/dev/null || echo false)
API_TOKEN=$(cat "$SEC/api-token")
DB_PASSWORD=$(cat "$SEC/db-password")
STAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# --- server.yaml --------------------------------------------------------------

if [ "$SERVER_CHANGED" = true ] || [ ! -e "$OUT/server.yaml" ]; then
	backup "$OUT/server.yaml"
	write_file 0600 "$OUT/server.yaml" <<EOF
# Written by hookmon-init.sh (mode: $MODE) on $STAMP for $NAME.
# Holds secrets: keep it mode 0600. Every key is described in
# deploy/server.example.yaml. hookmon-init.sh keeps this file on a re-run
# unless a secret in it changes, so local edits (connectors) survive.

grpc_addr: "$LISTEN_GRPC"
enroll_addr: "$LISTEN_ENROLL"
http_addr: "$LISTEN_HTTPS"
dashboard_dir: /usr/share/hookmon/dashboard

tls:
  cert_file: $CFG_PATH/tls/server.crt
  key_file: $CFG_PATH/tls/server.key
  ca_file: $CFG_PATH/tls/ca.crt
  ca_key_file: $CFG_PATH/tls/ca.key
  insecure: false

database:
  url: "postgres://hookmon:$DB_PASSWORD@$DB_HOST:5432/hookmon?sslmode=disable"

api:
  tokens:
    - "$API_TOKEN"
  allowed_origins: []

enrollment:
  cert_validity: 8760h
  tokens:
    - name: initial
      secret: "$ENROLL_TOKEN"
      expires: $ENROLL_EXPIRES
      single_use: $ENROLL_SINGLE_USE

watchdog:
  check_interval: 15s
  heartbeat_timeout: 60s

# SIEM connectors: copy the blocks you need from deploy/server.example.yaml.
connectors: {}
EOF
	created server.yaml
else
	chmod 0600 "$OUT/server.yaml"
	kept server.yaml
fi

# --- collector.yaml -----------------------------------------------------------

if [ ! -e "$OUT/collector.yaml" ]; then
	write_file 0644 "$OUT/collector.yaml" <<EOF
# Written by hookmon-init.sh (mode: $MODE) on $STAMP for $NAME.
# hookmon-init.sh never rewrites this file once it exists.

poll_interval: 30s
push_gateway: $PUSHGATEWAY
fleet_status_file: /var/lib/hookmon/fleet-status.json

# Every sensor bus to poll. There is no discovery: add each host here and
# restart the collector. For example:
#   hosts:
#     - hostname: web-01
#       status_url: http://web-01.example.internal:2112/status
hosts: []
EOF
	created collector.yaml
else
	kept collector.yaml
fi

if [ "$MODE" = compose ] && [ ! -e "$OUT/prometheus/buses.yml" ]; then
	write_file 0644 "$OUT/prometheus/buses.yml" <<'EOF'
# Sensor buses for Prometheus to scrape (/metrics on each bus's status port,
# 2112 by default). Prometheus re-reads this file when it changes.
# Replace the empty list with one group per set of hosts, for example:
#   - targets: ["web-01.example.internal:2112", "web-02.example.internal:2112"]
[]
EOF
	created prometheus/buses.yml
elif [ "$MODE" = compose ]; then
	kept prometheus/buses.yml
fi

# --- summary ------------------------------------------------------------------

FINGERPRINT=$(openssl x509 -noout -fingerprint -sha256 -in "$TLS/ca.crt" | sed 's/^[^=]*=//')
if [ "$ENROLL_SINGLE_USE" = true ]; then USES="single use"; else USES="reusable"; fi

cat <<EOF
HookMon appliance files in $OUT (mode $MODE)
  created: ${CREATED#, }
  kept:    ${KEPT#, }

CA certificate:  $TLS/ca.crt
  SHA-256 fingerprint $FINGERPRINT
Server certificate SANs: $SANS
Dashboard and REST API:  https://$NAME:$HTTPS_PORT/
  API token: $SEC/api-token
Enrollment token "initial": $USES, expires $ENROLL_EXPIRES

To enroll a sensor bus, copy $TLS/ca.crt to the bus host as
/etc/hookmon/ca.crt, then run there:

  sudo hookmon-bus --enroll-token $ENROLL_TOKEN \\
    --server-addr $NAME:$GRPC_PORT \\
    --enroll-addr $NAME:$ENROLL_PORT \\
    --ca-file /etc/hookmon/ca.crt \\
    --state-dir /var/lib/hookmon
EOF
if [ "$MODE" = compose ]; then
	cat <<EOF

Start the appliance:
  HOOKMON_CONFIG_DIR=$OUT docker compose -f deploy/appliance/docker-compose.yml up -d --build --wait
Grafana: port 3000 unless a compose override moves it; user admin, password
in $SEC/grafana.env
EOF
fi
