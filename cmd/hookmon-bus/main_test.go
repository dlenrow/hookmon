package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// secMainEnv makes the test binary run main() instead of the tests, so the
// test below runs hookmon-bus's real flag handling and exit path.
const secMainEnv = "HOOKMON_SEC_RUN_BUS_MAIN"

func TestMain(m *testing.M) {
	if os.Getenv(secMainEnv) == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// TestMain_RefusesPlaintext: a bus that is not in console mode and has no
// certificate, no enrollment token and no --insecure exits with status 1
// and names the ways to fix it. It refuses before any sensor starts, so the
// test needs no root.
func TestMain_RefusesPlaintext(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bus.yaml")
	cfg := fmt.Sprintf("status_port: 0\nstate_dir: %s\nfallback_log_path: %s\n",
		filepath.Join(dir, "state"), filepath.Join(dir, "fallback.jsonl"))
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(os.Args[0], "--config", cfgPath, "--server-addr", "127.0.0.1:1")
	cmd.Env = append(os.Environ(), secMainEnv+"=1")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 {
		t.Fatalf("hookmon-bus: got %v, want exit status 1; output:\n%s", err, out.String())
	}
	for _, want := range []string{"refusing to connect to the server without TLS", "--insecure", "--enroll-token"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output does not contain %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "sensor started") {
		t.Errorf("sensors started before the refusal:\n%s", out.String())
	}
}
