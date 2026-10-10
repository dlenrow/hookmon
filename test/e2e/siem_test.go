//go:build linux && e2e

package e2e

// SIEM connectors on the real stack (fix plan step 7d): a root
// hookmon-bus, enrolled, streaming to the real hookmon-server binary over
// mutual TLS, with PostgreSQL, and syslog and webhook receivers running in
// containers. A BPF canary load must arrive at both receivers, and
// stopping the bus must bring AGENT_OFFLINE to the webhook.
//
// It needs, besides what every e2e test needs:
//   - HOOKMON_TEST_PG_DSN: a PostgreSQL the test can create a schema in
//   - HOOKMON_SERVER_BIN: a built hookmon-server
//   - docker, and the Go toolchain (to build test/siemrecv)
//
// Without them it skips. The receivers run test/siemrecv, built static,
// in an alpine image pinned by digest (HOOKMON_SIEM_IMAGE overrides it).

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/dlenrow/hookmon/pkg/event"
	"github.com/dlenrow/hookmon/test/enrpki"
)

// siemImage runs the receivers: alpine 3.20, pinned by its index digest.
const siemImage = "alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"

func siemRandHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func siemFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func siemDocker(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// siemReceiver starts one siemrecv container and returns its name and the
// host address its port is published on.
func siemReceiver(t *testing.T, image, binDir, mode, port string) (name, addr string) {
	t.Helper()
	name = "hookmon-siem-" + mode + "-" + siemRandHex(t, 4)
	siemDocker(t, "run", "-d", "--name", name,
		"-p", "127.0.0.1::"+port+"/tcp",
		"-v", binDir+":/siem:ro",
		image, "/siem/siemrecv", mode, ":"+port)
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := exec.Command("docker", "logs", name).CombinedOutput()
			t.Logf("%s logs:\n%s", name, out)
		}
		exec.Command("docker", "rm", "-f", name).Run()
	})
	addr = siemDocker(t, "port", name, port+"/tcp")
	if i := strings.Index(addr, "\n"); i >= 0 {
		addr = addr[:i]
	}
	return name, addr
}

// siemLines returns the container's stdout lines that start with prefix,
// without it.
func siemLines(t *testing.T, name, prefix string) []string {
	t.Helper()
	out, err := exec.Command("docker", "logs", name).Output()
	if err != nil {
		t.Fatalf("docker logs %s: %v", name, err)
	}
	var lines []string
	for _, l := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(l, prefix+" ") {
			lines = append(lines, strings.TrimPrefix(l, prefix+" "))
		}
	}
	return lines
}

func siemWaitLine(t *testing.T, name, prefix string, timeout time.Duration, match func(string) bool) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		for _, l := range siemLines(t, name, prefix) {
			if match(l) {
				return l
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no matching %s line from %s after %v", prefix, name, timeout)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// siemSchema creates a schema for the test and returns a DSN using it.
func siemSchema(t *testing.T, dsn string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to HOOKMON_TEST_PG_DSN: %v", err)
	}
	defer conn.Close(ctx)
	schema := "siem_" + siemRandHex(t, 6)
	if _, err := conn.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if conn, err := pgx.Connect(ctx, dsn); err == nil {
			conn.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
			conn.Close(ctx)
		}
	})
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "search_path=" + schema
}

func siemWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// siemStart starts a process with its output in logPath, and stops it
// (SIGTERM, then SIGKILL) at cleanup.
func siemStart(t *testing.T, logPath string, bin string, args ...string) *exec.Cmd {
	t.Helper()
	logf, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, args...)
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", bin, err)
	}
	done := make(chan struct{})
	go func() { cmd.Wait(); logf.Close(); close(done) }()
	t.Cleanup(func() {
		cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			cmd.Process.Kill()
			<-done
		}
		if t.Failed() {
			out, _ := os.ReadFile(logPath)
			if len(out) > 8000 {
				out = out[len(out)-8000:]
			}
			t.Logf("%s log (tail):\n%s", filepath.Base(bin), out)
		}
	})
	return cmd
}

var siemSyslogLine = regexp.MustCompile(`^<(\d{1,3})>1 (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z) (\S+) hookmon - (\S+) - (CEF:0\|HookMon\|HookMon\|.*)$`)

func TestSIEM_RealStackCanaryReachesSyslogAndWebhook(t *testing.T) {
	dsn := os.Getenv("HOOKMON_TEST_PG_DSN")
	serverBin := os.Getenv("HOOKMON_SERVER_BIN")
	if dsn == "" || serverBin == "" {
		t.Skip("set HOOKMON_TEST_PG_DSN and HOOKMON_SERVER_BIN to run the SIEM real-stack test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not found")
	}
	image := siemImage
	if v := os.Getenv("HOOKMON_SIEM_IMAGE"); v != "" {
		image = v
	}
	dir := t.TempDir()

	// Receivers.
	binDir := filepath.Join(dir, "siembin")
	if err := os.Mkdir(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	build := exec.Command("go", "build", "-o", filepath.Join(binDir, "siemrecv"), "github.com/dlenrow/hookmon/test/siemrecv")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build siemrecv: %v\n%s", err, out)
	}
	sysName, sysAddr := siemReceiver(t, image, binDir, "syslog", "5514")
	hookName, hookAddr := siemReceiver(t, image, binDir, "webhook", "8080")
	t.Logf("syslog receiver %s on %s; webhook receiver %s on %s", sysName, sysAddr, hookName, hookAddr)

	// Server.
	pki := enrpki.New(t)
	apiToken, enrollToken := siemRandHex(t, 32), siemRandHex(t, 32)
	grpcAddr := fmt.Sprintf("127.0.0.1:%d", siemFreePort(t))
	enrollAddr := fmt.Sprintf("127.0.0.1:%d", siemFreePort(t))
	httpAddr := fmt.Sprintf("127.0.0.1:%d", siemFreePort(t))
	const timeout = 10 * time.Second
	serverYAML := filepath.Join(dir, "server.yaml")
	siemWrite(t, serverYAML, fmt.Sprintf(`grpc_addr: %q
enroll_addr: %q
http_addr: %q
dashboard_dir: ""
tls:
  cert_file: %s
  key_file: %s
  ca_file: %s
  ca_key_file: %s
database:
  url: %q
api:
  tokens: [%q]
enrollment:
  cert_validity: 24h
  tokens:
    - name: siem-e2e
      secret: %q
      expires: %s
watchdog:
  check_interval: 1s
  heartbeat_timeout: %s
connectors:
  syslog:
    address: %q
    protocol: tcp
  webhook:
    url: "http://%s/hook"
    headers:
      X-HookMon-Test: siem-e2e
`, grpcAddr, enrollAddr, httpAddr, pki.ServerCertFile, pki.ServerKeyFile, pki.CACertFile, pki.CAKeyFile,
		siemSchema(t, dsn), apiToken, enrollToken, time.Now().Add(time.Hour).UTC().Format(time.RFC3339), timeout, sysAddr, hookAddr))
	siemStart(t, filepath.Join(dir, "server.log"), serverBin, "--config", serverYAML)

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pki.CACertPEM)
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	api := func(path string, out any) int {
		req, _ := http.NewRequest(http.MethodGet, "https://"+httpAddr+path, nil)
		req.Header.Set("Authorization", "Bearer "+apiToken)
		resp, err := client.Do(req)
		if err != nil {
			return 0
		}
		defer resp.Body.Close()
		if out != nil && resp.StatusCode == http.StatusOK {
			json.NewDecoder(resp.Body).Decode(out)
		}
		return resp.StatusCode
	}
	waitFor := func(what string, d time.Duration, cond func() bool) {
		t.Helper()
		end := time.Now().Add(d)
		for !cond() {
			if time.Now().After(end) {
				t.Fatalf("timed out after %v waiting for %s", d, what)
			}
			time.Sleep(250 * time.Millisecond)
		}
	}
	waitFor("the server", 30*time.Second, func() bool { return api("/api/v1/health", nil) == http.StatusOK })

	// Root bus, enrolled, not in console mode.
	busYAML := filepath.Join(dir, "bus.yaml")
	siemWrite(t, busYAML, fmt.Sprintf("server_addr: %q\nenroll_addr: %q\nstate_dir: %s\nheartbeat_interval: 2s\ntls:\n  ca_file: %s\n",
		grpcAddr, enrollAddr, filepath.Join(dir, "state"), pki.CACertFile))
	busArgs := []string{"--config", busYAML, "--enroll-token", enrollToken}
	if p := statusPort(); p != "" {
		busArgs = append(busArgs, "--status-port", p)
	}
	bus := siemStart(t, filepath.Join(dir, "bus.log"), busBin(), busArgs...)

	var hostID string
	waitFor("the bus to enroll and come online", 60*time.Second, func() bool {
		var hosts []*event.Host
		if api("/api/v1/hosts", &hosts) != http.StatusOK {
			return false
		}
		for _, h := range hosts {
			if h.Status == event.HostOnline {
				hostID = h.ID
				return true
			}
		}
		return false
	})
	t.Logf("bus enrolled as host %s", hostID)
	time.Sleep(3 * time.Second) // sensors attached

	// The canary.
	if err := LoadCanary(canaryBinDir()+"/load_canary", canaryDir()+"/hello_bpf.o",
		"syscalls", "sys_enter_getpid", "hello_count"); err != nil {
		t.Fatalf("load canary: %v", err)
	}

	sys := siemWaitLine(t, sysName, "SYSLOG", 30*time.Second, func(l string) bool {
		return strings.Contains(l, " - BPF_LOAD - ") && strings.Contains(l, "cs2=hello_count")
	})
	t.Logf("syslog receiver got: %s", sys)
	m := siemSyslogLine.FindStringSubmatch(sys)
	if m == nil {
		t.Fatalf("not an RFC 5424 message with CEF: %q", sys)
	}
	hostname, _ := os.Hostname()
	if m[1] != "130" || m[3] != hostname || m[4] != "BPF_LOAD" {
		t.Errorf("RFC 5424 header: PRI %s (want 130: local0, critical), HOSTNAME %s (want %s), MSGID %s", m[1], m[3], hostname, m[4])
	}
	for _, want := range []string{"|BPF_LOAD|BPF Program Loaded|10|", "deviceExternalId=" + hostID, "cs4Label=PolicyResult cs4=ALERT", "cs5Label=ProgTag cs5="} {
		if !strings.Contains(m[5], want) {
			t.Errorf("CEF lacks %q", want)
		}
	}

	hook := siemWaitLine(t, hookName, "WEBHOOK", 30*time.Second, func(l string) bool {
		return strings.Contains(l, `"event_type":"BPF_LOAD"`) && strings.Contains(l, `"prog_name":"hello_count"`)
	})
	t.Logf("webhook receiver got: %s", hook)
	var got event.HookEvent
	if err := json.Unmarshal([]byte(hook), &got); err != nil {
		t.Fatalf("webhook body: %v", err)
	}
	if got.HostID != hostID || got.Severity != event.SeverityCritical || got.PolicyResult == nil ||
		got.PolicyResult.Action != event.ActionAlert || got.BPFDetail == nil || got.BPFDetail.ProgHash == "" {
		t.Errorf("webhook event: %+v", got)
	}

	// Stop the bus: AGENT_OFFLINE reaches the webhook.
	bus.Process.Signal(syscall.SIGTERM)
	stopped := time.Now()
	off := siemWaitLine(t, hookName, "WEBHOOK", timeout+20*time.Second, func(l string) bool {
		return strings.Contains(l, `"event_type":"AGENT_OFFLINE"`) && strings.Contains(l, `"host_id":"`+hostID+`"`)
	})
	t.Logf("AGENT_OFFLINE reached the webhook %v after SIGTERM: %s", time.Since(stopped).Round(100*time.Millisecond), off)
	sysOff := siemWaitLine(t, sysName, "SYSLOG", 10*time.Second, func(l string) bool {
		return strings.Contains(l, " - AGENT_OFFLINE - ") && strings.Contains(l, "deviceExternalId="+hostID)
	})
	t.Logf("syslog receiver got: %s", sysOff)
}
