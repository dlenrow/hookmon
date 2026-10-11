package main

import (
	"bytes"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
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

// TestMain_ConnectorInitFailureFailsStartup: a connector that cannot start
// (here a syslog receiver nothing listens on) stops hookmon-server with
// status 1, before it touches the database. The old server discarded the
// error and ran without the connector.
func TestMain_ConnectorInitFailureFailsStartup(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	cfg := filepath.Join(t.TempDir(), "server.yaml")
	body := "connectors:\n  syslog:\n    address: \"" + addr + "\"\n    protocol: tcp\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out := secRunMain(t, "--config", cfg, "--insecure", "--db", "postgres://nobody@127.0.0.1:1/none",
		"--grpc-addr", "127.0.0.1:0", "--http-addr", "127.0.0.1:0", "--dashboard-dir", "")
	if code != 1 {
		t.Errorf("exit status %d, want 1; output:\n%s", code, out)
	}
	for _, want := range []string{"start connectors", "connectors.syslog", addr} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not contain %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "connect to database") {
		t.Errorf("server reached the database before failing on the connector:\n%s", out)
	}
}

// TestMain_BadConnectorConfigFailsStartup: an invalid connectors section
// is rejected when the config file loads.
func TestMain_BadConnectorConfigFailsStartup(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "server.yaml")
	if err := os.WriteFile(cfg, []byte("connectors:\n  splunk:\n    url: https://splunk:8088/services/collector/event\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out := secRunMain(t, "--config", cfg, "--insecure")
	if code != 1 || !strings.Contains(out, "failed to load config") || !strings.Contains(out, "connectors.splunk: token is required") {
		t.Errorf("exit status %d; output:\n%s", code, out)
	}
}

// TestMain_RefusesEmptyAPIToken: a stray comma in --api-tokens, or a token
// of only spaces, stops hookmon-server with status 1 before it touches the
// database. The old server kept the empty token, and then accepted a
// request whose bearer token was empty.
func TestMain_RefusesEmptyAPIToken(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "server.yaml")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tokens := range []string{"good-token,", ",good-token", "good-token, ,other"} {
		code, out := secRunMain(t, "--config", empty, "--insecure", "--api-tokens", tokens,
			"--db", "postgres://nobody@127.0.0.1:1/none", "--grpc-addr", "127.0.0.1:0", "--http-addr", "127.0.0.1:0", "--dashboard-dir", "")
		if code != 1 {
			t.Errorf("--api-tokens %q: exit status %d, want 1; output:\n%s", tokens, code, out)
		}
		for _, want := range []string{"invalid configuration", "api.tokens", "is empty"} {
			if !strings.Contains(out, want) {
				t.Errorf("--api-tokens %q: output does not contain %q:\n%s", tokens, want, out)
			}
		}
		if strings.Contains(out, "database") {
			t.Errorf("--api-tokens %q: server reached the database before refusing:\n%s", tokens, out)
		}
	}
}

// TestSplitAPITokens: entries are trimmed; empty ones are kept for
// Validate to refuse; an empty flag means no tokens.
func TestSplitAPITokens(t *testing.T) {
	for in, want := range map[string][]string{
		"":              nil,
		"a":             {"a"},
		"a,b":           {"a", "b"},
		" a , b ":       {"a", "b"},
		"a,":            {"a", ""},
		"a, ,b":         {"a", "", "b"},
		",":             {"", ""},
		"tok-1,\ttok-2": {"tok-1", "tok-2"},
	} {
		if got := splitAPITokens(in); !reflect.DeepEqual(got, want) {
			t.Errorf("splitAPITokens(%q) = %q, want %q", in, got, want)
		}
	}
}
