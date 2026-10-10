package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// secMainEnv makes the test binary run main() instead of the tests, so the
// tests below run hookmon-server's real flag handling and exit path.
const secMainEnv = "HOOKMON_SEC_RUN_SERVER_MAIN"

func TestMain(m *testing.M) {
	if os.Getenv(secMainEnv) == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func secRunMain(t *testing.T, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), secMainEnv+"=1")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0, out.String()
	case errors.As(err, &exit):
		return exit.ExitCode(), out.String()
	default:
		t.Fatalf("run hookmon-server: %v", err)
		return 0, ""
	}
}

// TestMain_RefusesWithoutTLS: hookmon-server with no certificate and no
// --insecure exits with status 1 and says how to fix it, before it touches
// the database.
func TestMain_RefusesWithoutTLS(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "server.yaml")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out := secRunMain(t, "--config", empty, "--db", "postgres://nobody@127.0.0.1:1/none")
	if code != 1 {
		t.Errorf("exit status %d, want 1; output:\n%s", code, out)
	}
	for _, want := range []string{"refusing to start without TLS", "--insecure", "tls.cert_file"} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not contain %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "database") {
		t.Errorf("server reached the database before refusing:\n%s", out)
	}
}
