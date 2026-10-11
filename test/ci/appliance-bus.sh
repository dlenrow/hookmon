#!/usr/bin/env bash
# appliance-bus.sh: enroll a real hookmon-bus into a running compose
# appliance on this host, so the dashboard smoke tests (dashboard/e2e) have
# a monitored host, events, live events and PENDING entries to show. CI's
# "Dashboard e2e" job runs it; it runs the same way by hand.
#
#   test/ci/appliance-bus.sh start --config-dir DIR --hostname NAME --bus BIN --work-dir DIR [options]
#   test/ci/appliance-bus.sh stop --work-dir DIR
#
# start:
#   1. starts fleet learning mode through the REST API (2 hours), so what
#      the bus reports becomes PENDING allowlist entries;
#   2. starts the bus as root (sudo -n), enrolling with the appliance's
#      enrollment token file; it dials 127.0.0.1 and checks the server
#      certificate for NAME;
#   3. waits until the host is ONLINE and prints each sensor's state from
#      its heartbeat (a sensor that is not alive is a warning, not a
#      failure: the dashboard tests do not depend on it);
#   4. starts a loop that runs /bin/true with LD_PRELOAD once a second, so
#      the exec_injection sensor keeps producing live events;
#   5. waits for stored events and a PENDING entry.
# stop: stops the loop and the bus, and prints the end of the bus log.
#
# Options for start (the ports are the appliance's published ports):
#   --config-dir DIR    hookmon-init.sh --out-dir (tls/ca.crt, secrets/)
#   --hostname NAME     the appliance's --hostname (server certificate name)
#   --bus BIN           hookmon-bus, built with its eBPF objects
#   --work-dir DIR      bus config, state, log and pid files go here
#   --https-port N      default 8443
#   --grpc-port N       default 9443
#   --enroll-port N     default 9444
#   --status-port N     the bus's /status port, on 127.0.0.1 (default 2112)
#   --timeout SECONDS   how long each wait lasts (default 120)

set -euo pipefail

die() {
	echo "appliance-bus: $*" >&2
	exit 1
}

usage() {
	sed -n '2,/^$/s/^# \{0,1\}//p' "$0" >&2
	exit 2
}

[ $# -ge 1 ] || usage
CMD=$1
shift

CONFIG_DIR='' NAME='' BUS='' WORK='' HTTPS=8443 GRPC=9443 ENROLL=9444 STATUS=2112 TIMEOUT=120
while [ $# -gt 0 ]; do
	[ $# -ge 2 ] || usage
	case $1 in
	--config-dir) CONFIG_DIR=$2 ;;
	--hostname) NAME=$2 ;;
	--bus) BUS=$2 ;;
	--work-dir) WORK=$2 ;;
	--https-port) HTTPS=$2 ;;
	--grpc-port) GRPC=$2 ;;
	--enroll-port) ENROLL=$2 ;;
	--status-port) STATUS=$2 ;;
	--timeout) TIMEOUT=$2 ;;
	*) usage ;;
	esac
	shift 2
done
[ -n "$WORK" ] || usage

stop() {
	if [ -s "$WORK/activity.pid" ]; then
		kill "$(cat "$WORK/activity.pid")" 2>/dev/null || true
		rm -f "$WORK/activity.pid"
	fi
	if [ -s "$WORK/bus.pid" ]; then
		pid=$(cat "$WORK/bus.pid")
		sudo -n kill -TERM "$pid" 2>/dev/null || true
		for _ in $(seq 30); do
			sudo -n kill -0 "$pid" 2>/dev/null || break
			sleep 1
		done
		sudo -n kill -KILL "$pid" 2>/dev/null || true
		rm -f "$WORK/bus.pid"
	fi
	if [ -f "$WORK/bus.log" ]; then
		echo "--- bus log (last 40 lines) ---"
		tail -n 40 "$WORK/bus.log"
	fi
}

case $CMD in
stop)
	stop
	exit 0
	;;
start) ;;
*) usage ;;
esac

if [ -z "$CONFIG_DIR" ] || [ -z "$NAME" ] || [ -z "$BUS" ]; then
	usage
fi
CA=$CONFIG_DIR/tls/ca.crt
TOKEN_FILE=$CONFIG_DIR/secrets/enroll-token
[ -r "$CA" ] || die "no CA certificate at $CA"
[ -r "$CONFIG_DIR/secrets/api-token" ] || die "no API token in $CONFIG_DIR/secrets"
[ -r "$TOKEN_FILE" ] || die "no enrollment token at $TOKEN_FILE"
[ -x "$BUS" ] || die "no hookmon-bus at $BUS"
command -v jq >/dev/null || die "jq is needed"
API_TOKEN=$(cat "$CONFIG_DIR/secrets/api-token")
mkdir -p "$WORK"
WORK=$(cd "$WORK" && pwd)

# api METHOD PATH [BODY]: an authenticated REST call, verified against the
# CA and the appliance's name. Prints the body; fails on an HTTP error.
api() {
	local args=(-sS --fail-with-body --max-time 10 --cacert "$CA" --resolve "$NAME:$HTTPS:127.0.0.1"
		-H "Authorization: Bearer $API_TOKEN" -X "$1")
	if [ $# -ge 3 ]; then
		args+=(-H "Content-Type: application/json" --data "$3")
	fi
	curl "${args[@]}" "https://$NAME:$HTTPS$2"
}

# wait_for WHAT COMMAND...: retry COMMAND every 2 s until it succeeds.
wait_for() {
	local what=$1 end=$((SECONDS + TIMEOUT))
	shift
	until "$@"; do
		if [ $SECONDS -ge $end ]; then
			echo "timed out after ${TIMEOUT}s waiting for $what" >&2
			stop >&2
			exit 1
		fi
		sleep 2
	done
}

echo "==> Fleet learning mode on"
api PUT /api/v1/learning/fleet '{"duration":"2h"}' | jq -c .

echo "==> Starting hookmon-bus as root"
cat >"$WORK/bus.yaml" <<EOF
server_addr: "127.0.0.1:$GRPC"
enroll_addr: "127.0.0.1:$ENROLL"
state_dir: "$WORK/state"
heartbeat_interval: 5s
status_addr: "127.0.0.1"
status_port: $STATUS
tls:
  ca_file: "$CA"
  server_name: "$NAME"
EOF
: >"$WORK/bus.log"
# sh -c records the bus's own PID (exec keeps it), not sudo's.
sudo -n sh -c 'echo $$ >"$1"; exec "$2" --config "$3" --enroll-token-file "$4" >>"$5" 2>&1' \
	sh "$WORK/bus.pid" "$BUS" "$WORK/bus.yaml" "$TOKEN_FILE" "$WORK/bus.log" &
sleep 1
[ -s "$WORK/bus.pid" ] || die "the bus did not start; see $WORK/bus.log"

host_online() {
	api GET /api/v1/hosts 2>/dev/null >"$WORK/hosts.json" &&
		jq -e 'map(select(.status == "ONLINE" and ((.sensors // []) | length) > 0)) | length > 0' "$WORK/hosts.json" >/dev/null
}
wait_for "the bus to enroll and report its sensors" host_online
echo "==> Host online; sensors from its heartbeat:"
jq -r '.[] | select(.status == "ONLINE") | "  \(.hostname) \(.id)", (.sensors[] | "    \(.name): \(.status)\(if .reason then " (" + .reason + ")" else "" end)")' "$WORK/hosts.json"
# Give the sensors one more heartbeat to come alive, then report.
sleep 12
api GET /api/v1/hosts >"$WORK/hosts.json"
not_alive=$(jq -r '[.[] | select(.status == "ONLINE") | .sensors[] | select(.status != "alive") | "\(.name)=\(.status)\(if .reason then " (" + .reason + ")" else "" end)"] | join(", ")' "$WORK/hosts.json")
alive=$(jq '[.[] | select(.status == "ONLINE") | .sensors[] | select(.status == "alive")] | length' "$WORK/hosts.json")
total=$(jq '[.[] | select(.status == "ONLINE") | .sensors[]] | length' "$WORK/hosts.json")
echo "==> $alive of $total sensors alive"
if [ -n "$not_alive" ]; then
	echo "::warning title=hookmon-bus sensors::$alive of $total sensors alive; not alive: $not_alive"
fi

echo "==> Starting the activity loop (LD_PRELOAD exec every second)"
(
	while :; do
		LD_PRELOAD=/nonexistent/hookmon-ci-activity.so /bin/true 2>/dev/null || true
		sleep 1
	done
) &
echo $! >"$WORK/activity.pid"

events_and_pending() {
	local ev pend
	ev=$(api GET '/api/v1/events?limit=10' 2>/dev/null | jq length) || return 1
	pend=$(api GET '/api/v1/policies?status=PENDING' 2>/dev/null | jq length) || return 1
	[ "$ev" -gt 0 ] && [ "$pend" -gt 0 ]
}
wait_for "events and a PENDING entry" events_and_pending
echo "==> $(api GET '/api/v1/events?limit=200' | jq length) events stored (first 200), $(api GET '/api/v1/policies?status=PENDING' | jq length) PENDING entries"
