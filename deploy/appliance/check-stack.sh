#!/usr/bin/env bash
# check-stack.sh: smoke checks for a running compose appliance. CI runs it
# after `docker compose up --wait`; run it by hand the same way.
#
# Usage:
#   deploy/appliance/check-stack.sh --config-dir DIR --hostname NAME -- COMPOSE...
#
# DIR and NAME are what hookmon-init.sh was given. COMPOSE is the compose
# command for the stack, for example:
#   docker compose -p hookmon -f deploy/appliance/docker-compose.yml
# Published ports are read with `COMPOSE port`, so the checks follow any
# port override. Every check runs; the exit status is 1 if any failed.

set -uo pipefail

CONFIG_DIR=
NAME=
while [ $# -gt 0 ]; do
	case $1 in
	--config-dir) CONFIG_DIR=$2; shift 2 ;;
	--hostname) NAME=$2; shift 2 ;;
	--) shift; break ;;
	*) echo "usage: $0 --config-dir DIR --hostname NAME -- COMPOSE..." >&2; exit 2 ;;
	esac
done
COMPOSE=("$@")
if [ -z "$CONFIG_DIR" ] || [ -z "$NAME" ] || [ ${#COMPOSE[@]} -eq 0 ]; then
	echo "usage: $0 --config-dir DIR --hostname NAME -- COMPOSE..." >&2
	exit 2
fi

CA=$CONFIG_DIR/tls/ca.crt
API_TOKEN=$(cat "$CONFIG_DIR/secrets/api-token")
GRAFANA_PASSWORD=$(sed -n 's/^GF_SECURITY_ADMIN_PASSWORD=//p' "$CONFIG_DIR/secrets/grafana.env")

FAILED=0
pass() { printf 'ok    %-34s %s\n' "$1" "$2"; }
fail() { printf 'FAIL  %-34s %s\n' "$1" "$2"; FAILED=1; }

# published SERVICE PORT: the host port COMPOSE publishes it on, or empty.
published() {
	local out
	out=$("${COMPOSE[@]}" port "$1" "$2" 2>/dev/null | head -n 1) || return 0
	out=${out##*:}
	[ "$out" = 0 ] && out=
	printf '%s' "$out"
}

# retry SECONDS CMD...: run CMD every 2 s until it succeeds or time runs out.
retry() {
	local end=$((SECONDS + $1))
	shift
	until "$@"; do
		[ $SECONDS -lt "$end" ] || return 1
		sleep 2
	done
}

HTTPS=$(published server 8443)
ENROLL=$(published server 9444)
GRAFANA=$(published grafana 3000)
PROM=$(published prometheus 9090)
PUSHGW=$(published pushgateway 9091)
AM=$(published alertmanager 9093)
LOKI=$(published loki 3100)
echo "published ports: https=$HTTPS enroll=$ENROLL grafana=$GRAFANA prometheus=$PROM pushgateway=$PUSHGW alertmanager=$AM loki=$LOKI"

# The server certificate names $NAME; dial it at 127.0.0.1.
srv() {
	curl -sS --max-time 10 --cacert "$CA" --resolve "$NAME:$HTTPS:127.0.0.1" "$@"
}

# --- files ---
bad=
for p in "$CONFIG_DIR/server.yaml" "$CONFIG_DIR/tls/ca.key" "$CONFIG_DIR/tls/server.key" "$CONFIG_DIR"/secrets/*; do
	m=$(stat -c %a "$p")
	[ "$m" = 600 ] || bad="$bad ${p#"$CONFIG_DIR"/}=$m"
done
if [ -z "$bad" ]; then pass "secret files are 0600" "server.yaml, tls/*.key, secrets/*"; else fail "secret files are 0600" "$bad"; fi

# --- Postgres ---
pg=$(published postgres 5432)
if [ -z "$pg" ]; then pass "postgres not published" "no host port for 5432"; else fail "postgres not published" "published on $pg"; fi

# --- server ---
body=$(srv -f "https://$NAME:$HTTPS/api/v1/health" 2>&1)
if [ "$body" = '{"status":"ok"}' ]; then pass "server health over TLS" "$body (verified with $CA)"; else fail "server health over TLS" "$body"; fi

index=$(srv -f "https://$NAME:$HTTPS/" 2>&1)
asset=$(printf '%s' "$index" | grep -o '/assets/[^"]*\.js' | head -n 1)
if printf '%s' "$index" | grep -q '<div id="root"></div>' && [ -n "$asset" ]; then
	code=$(srv -o /dev/null -w '%{http_code}' "https://$NAME:$HTTPS$asset")
	if [ "$code" = 200 ]; then
		pass "dashboard index" "$(printf '%s' "$index" | grep -o '<title>[^<]*</title>'), $asset 200"
	else
		fail "dashboard index" "$asset returned $code"
	fi
else
	fail "dashboard index" "$(printf '%s' "$index" | head -c 200)"
fi

code=$(srv -o /dev/null -w '%{http_code}' "https://$NAME:$HTTPS/api/v1/settings")
settings=$(srv -f -H "Authorization: Bearer $API_TOKEN" "https://$NAME:$HTTPS/api/v1/settings" 2>&1)
if [ "$code" = 401 ] && printf '%s' "$settings" | grep -q '"tls":true'; then
	pass "API token" "no token 401; with secrets/api-token 200, tls true"
else
	fail "API token" "no token $code; with token: $(printf '%s' "$settings" | head -c 200)"
fi

verify=$(openssl s_client -connect "127.0.0.1:$ENROLL" -servername "$NAME" -verify_hostname "$NAME" \
	-CAfile "$CA" -verify_return_error </dev/null 2>&1 | grep -m 1 'Verify return code')
if printf '%s' "$verify" | grep -q 'Verify return code: 0 (ok)'; then
	pass "enrollment listener TLS" "$NAME:$ENROLL, $(printf '%s' "$verify" | sed 's/^ *//')"
else
	fail "enrollment listener TLS" "${verify:-no handshake}"
fi

# --- Grafana ---
health=$(curl -sS --max-time 10 "http://127.0.0.1:$GRAFANA/api/health" 2>&1)
if printf '%s' "$health" | grep -q '"database": *"ok"'; then
	pass "grafana health" "$(printf '%s' "$health" | tr -d ' \n')"
else
	fail "grafana health" "$health"
fi
ds=$(curl -sS --max-time 10 -u "admin:$GRAFANA_PASSWORD" "http://127.0.0.1:$GRAFANA/api/datasources" 2>&1)
dash=$(curl -sS --max-time 10 -o /dev/null -w '%{http_code}' -u "admin:$GRAFANA_PASSWORD" \
	"http://127.0.0.1:$GRAFANA/api/dashboards/uid/hookmon-main")
if printf '%s' "$ds" | grep -q '"uid":"loki"' && printf '%s' "$ds" | grep -q '"uid":"prometheus"' && [ "$dash" = 200 ]; then
	pass "grafana provisioning" "datasources loki and prometheus, dashboard hookmon-main (admin login)"
else
	fail "grafana provisioning" "dashboard $dash; datasources $(printf '%s' "$ds" | head -c 200)"
fi

# --- Prometheus ---
target_up() {
	curl -sS --max-time 10 "http://127.0.0.1:$PROM/api/v1/targets?state=active&scrapePool=hookmon-collector" |
		grep -q '"health":"up"'
}
if retry 60 target_up; then
	pass "prometheus targets" "hookmon-collector (pushgateway:9091) up"
else
	fail "prometheus targets" "$(curl -sS "http://127.0.0.1:$PROM/api/v1/targets?state=active" | head -c 300)"
fi
am_found() {
	curl -sS --max-time 10 "http://127.0.0.1:$PROM/api/v1/alertmanagers" | grep -q 'alertmanager:9093'
}
# Every alert in deploy/docker/grafana/alerts is loaded.
want=$(cat "$(dirname "$0")"/../docker/grafana/alerts/*.yaml | grep -c '^ *- alert: ')
rules=$(curl -sS --max-time 10 "http://127.0.0.1:$PROM/api/v1/rules?type=alert" | grep -o '"name":"HookMon[A-Za-z0-9]*"' | sort -u | wc -l)
if retry 30 am_found && [ "$rules" -eq "$want" ]; then
	pass "prometheus rules and alertmanager" "$rules of $want alert rules loaded; alertmanager:9093 active"
else
	fail "prometheus rules and alertmanager" "$rules of $want alert rules; $(curl -sS "http://127.0.0.1:$PROM/api/v1/alertmanagers")"
fi

# --- Alertmanager ---
status=$(curl -sS --max-time 10 -w ' %{http_code}' "http://127.0.0.1:$AM/api/v2/status" 2>&1)
if [ "${status##* }" = 200 ] && printf '%s' "$status" | grep -q '"uptime"'; then
	pass "alertmanager status" "200, $(printf '%s' "$status" | grep -o '"version":"[^"]*"' | head -n 1)"
else
	fail "alertmanager status" "$(printf '%s' "$status" | head -c 200)"
fi

# --- Pushgateway ---
pushed() {
	curl -sS --max-time 10 "http://127.0.0.1:$PUSHGW/metrics" |
		grep '^push_time_seconds{.*job="hookmon-collector"' |
		awk '$2 + 0 > 0 { print $2; found = 1 } END { exit !found }'
}
if pt=$(retry 60 pushed); then
	pass "collector pushed to pushgateway" "push_time_seconds=$pt ($(awk -v t="$pt" -v now="$(date +%s)" 'BEGIN { printf "%d s ago", now - t }'))"
else
	fail "collector pushed to pushgateway" "no push_time_seconds for job hookmon-collector"
fi

# --- Loki ---
ready=$(curl -sS --max-time 10 "http://127.0.0.1:$LOKI/ready" 2>&1)
if [ "$ready" = ready ]; then pass "loki ready" "$ready"; else fail "loki ready" "$ready"; fi

if [ $FAILED -ne 0 ]; then
	echo "check-stack: FAILED"
	exit 1
fi
echo "check-stack: all checks passed"
