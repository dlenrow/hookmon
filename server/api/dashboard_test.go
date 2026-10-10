package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
)

const (
	secIndexHTML = "<!doctype html><title>HookMon</title><div id=root></div>"
	secAppJS     = "console.log('hookmon');"
)

// secDashDir writes a small dashboard build, plus a file next to it that
// must never be served.
func secDashDir(t *testing.T) string {
	t.Helper()
	parent := t.TempDir()
	dir := filepath.Join(parent, "dist")
	for name, body := range map[string]string{
		"index.html":    secIndexHTML,
		"assets/app.js": secAppJS,
	} {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(parent, "secret.txt"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func secRouter(t *testing.T, dashDir string) http.Handler {
	t.Helper()
	var dash http.Handler
	if dashDir != "" {
		d, err := NewDashboard(dashDir)
		if err != nil {
			t.Fatal(err)
		}
		dash = d
	}
	return NewServer(nil, zap.NewNop(), nil).Router([]string{"tok"}, dash)
}

func secDo(t *testing.T, h http.Handler, method, target string) (int, string, http.Header) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	body, _ := io.ReadAll(rec.Result().Body)
	return rec.Code, string(body), rec.Header()
}

// TestRouter_Dashboard checks which paths the dashboard serves: its files,
// index.html for "/" and for client-side routes, and never an API path.
func TestRouter_Dashboard(t *testing.T) {
	h := secRouter(t, secDashDir(t))

	index := []string{"/", "/index.html", "/events", "/events/0b6c1f2e-1234", "/hosts", "/policies", "/settings", "/assets", "/no/such/page", "/../secret.txt"}
	for _, p := range index {
		code, body, hdr := secDo(t, h, http.MethodGet, p)
		if code != http.StatusOK || body != secIndexHTML {
			t.Errorf("GET %s: status %d, body %q; want index.html", p, code, body)
		}
		if ct := hdr.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Errorf("GET %s: Content-Type %q", p, ct)
		}
	}

	code, body, hdr := secDo(t, h, http.MethodGet, "/assets/app.js")
	if code != http.StatusOK || body != secAppJS || !strings.Contains(hdr.Get("Content-Type"), "javascript") {
		t.Errorf("GET /assets/app.js: status %d, Content-Type %q, body %q", code, hdr.Get("Content-Type"), body)
	}
	if code, _, _ := secDo(t, h, http.MethodHead, "/hosts"); code != http.StatusOK {
		t.Errorf("HEAD /hosts: status %d", code)
	}
	if code, _, _ := secDo(t, h, http.MethodPost, "/hosts"); code != http.StatusMethodNotAllowed {
		t.Errorf("POST /hosts: status %d, want 405", code)
	}

	// API paths: unknown ones are a JSON 404, never index.html; known ones
	// still route (and still need a token).
	for _, p := range []string{"/api", "/api/", "/api/v1", "/api/v1/nope", "/api/v1/hosts/x/y", "/api/v2/events", "/x/../api/v1/nope"} {
		code, body, _ := secDo(t, h, http.MethodGet, p)
		if code != http.StatusNotFound || body != `{"error":"not found"}` {
			t.Errorf("GET %s: status %d, body %q; want a JSON 404", p, code, body)
		}
	}
	if code, body, _ := secDo(t, h, http.MethodGet, "/api/v1/health"); code != http.StatusOK || !strings.Contains(body, "ok") {
		t.Errorf("GET /api/v1/health: status %d, body %q", code, body)
	}
	if code, _, _ := secDo(t, h, http.MethodGet, "/api/v1/hosts"); code != http.StatusUnauthorized {
		t.Errorf("GET /api/v1/hosts without a token: status %d, want 401", code)
	}
}

// TestRouter_NoDashboard: with no dashboard, every unknown path is a 404.
func TestRouter_NoDashboard(t *testing.T) {
	h := secRouter(t, "")
	for _, p := range []string{"/", "/hosts", "/api/v1/nope"} {
		if code, body, _ := secDo(t, h, http.MethodGet, p); code != http.StatusNotFound || body != `{"error":"not found"}` {
			t.Errorf("GET %s: status %d, body %q; want a JSON 404", p, code, body)
		}
	}
}

func TestNewDashboard_NeedsIndex(t *testing.T) {
	if _, err := NewDashboard(t.TempDir()); err == nil {
		t.Error("NewDashboard accepted a directory without index.html")
	}
	if _, err := NewDashboard(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("NewDashboard accepted a missing directory")
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "index.html"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDashboard(dir); err == nil {
		t.Error("NewDashboard accepted index.html as a directory")
	}
}
