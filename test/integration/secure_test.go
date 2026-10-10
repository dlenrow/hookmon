package integration_test

import (
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dlenrow/hookmon/pkg/event"
	"github.com/dlenrow/hookmon/test/enrpki"
)

const (
	secIndexHTML = "<!doctype html><title>HookMon</title><div id=root></div>"
	secAppJS     = "console.log('hookmon');"
)

func secDashboardDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte(secIndexHTML), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "assets", "app.js"), []byte(secAppJS), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func secGet(t *testing.T, c *http.Client, url string) (int, string) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// TestIntegration_RESTOverTLSServesDashboard runs the real server with TLS
// and a dashboard directory. The REST API and the dashboard share one TLS
// listener: "/" and client-side routes get index.html, assets are served,
// unknown API paths are a 404, and plain HTTP to the port gets no API
// response.
func TestIntegration_RESTOverTLSServesDashboard(t *testing.T) {
	dsn := enrPGDSN(t)
	pki := enrpki.New(t)
	cfg := enrServerConfig(pki, dsn, enrNewTokens(t))
	cfg.DashboardDir = secDashboardDir(t)
	s := enrStartServer(t, cfg)
	base := "https://" + s.HTTPAddr()

	for _, p := range []string{"/", "/hosts", "/events/some-event-id", "/settings"} {
		if code, body := secGet(t, s.client, base+p); code != http.StatusOK || body != secIndexHTML {
			t.Errorf("GET %s: status %d, body %q; want index.html", p, code, body)
		}
	}
	if code, body := secGet(t, s.client, base+"/assets/app.js"); code != http.StatusOK || body != secAppJS {
		t.Errorf("GET /assets/app.js: status %d, body %q", code, body)
	}
	if code, body := secGet(t, s.client, base+"/api/v1/no-such-endpoint"); code != http.StatusNotFound || strings.Contains(body, "<title>") {
		t.Errorf("GET /api/v1/no-such-endpoint: status %d, body %q; want a 404 that is not index.html", code, body)
	}
	if code, body := secGet(t, s.client, base+"/api/v1/health"); code != http.StatusOK || !strings.Contains(body, "ok") {
		t.Errorf("GET /api/v1/health: status %d, body %q", code, body)
	}
	var hosts []*event.Host
	if code := enrGet(t, s, "/api/v1/hosts", &hosts); code != http.StatusOK {
		t.Errorf("authenticated GET /api/v1/hosts over TLS: status %d", code)
	}

	plain := &http.Client{Timeout: 10 * time.Second}
	if resp, err := plain.Get("http://" + s.HTTPAddr() + "/api/v1/health"); err == nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK || strings.Contains(string(body), `"status":"ok"`) {
			t.Errorf("plain HTTP to the REST port answered: status %d, body %q", resp.StatusCode, body)
		}
	}
}

// TestIntegration_UnknownUIDEventStored sends an exec_injection event with
// UID 4294967295 ("unknown" since step 4) through a real enrolled bus
// transport, mutual TLS, the server and PostgreSQL. Before the BIGINT
// migration the insert failed and the event was lost.
func TestIntegration_UnknownUIDEventStored(t *testing.T) {
	dsn := enrPGDSN(t)
	pki := enrpki.New(t)
	tok := enrNewTokens(t)
	s := enrStartServer(t, enrServerConfig(pki, dsn, tok))
	bus := enrEnroll(t, s, pki, tok.reusable)
	tr, _ := enrRunBus(t, bus, nil)

	evt := &event.HookEvent{
		ID:        "unknown-uid-1",
		Timestamp: time.Now(),
		HostID:    bus.HostID,
		Hostname:  "bus",
		EventType: event.EventExecInjection,
		Severity:  event.SeverityAlert,
		PID:       4242,
		PPID:      1,
		UID:       math.MaxUint32,
		GID:       math.MaxUint32,
		Comm:      "sh",
		ExecInjectionDetail: &event.ExecInjectionDetail{
			LibraryPath:  "/tmp/evil.so",
			TargetBinary: "/usr/bin/true",
			SetBy:        "env",
			EnvVar:       "LD_PRELOAD",
		},
	}
	if err := tr.SendEvent(evt); err != nil {
		t.Fatal(err)
	}
	enrWaitFor(t, 10*time.Second, "the unknown-UID event in the store", func() bool {
		return len(enrEvents(t, s, "host_id="+bus.HostID)) == 1
	})
	got := enrEvents(t, s, "host_id="+bus.HostID)[0]
	if got.ID != evt.ID || got.UID != math.MaxUint32 || got.GID != math.MaxUint32 || got.PID != 4242 {
		t.Errorf("stored event: id %s pid %d uid %d gid %d", got.ID, got.PID, got.UID, got.GID)
	}
	if got.ExecInjectionDetail == nil || got.ExecInjectionDetail.EnvVar != "LD_PRELOAD" {
		t.Errorf("exec injection detail: %+v", got.ExecInjectionDetail)
	}
}
