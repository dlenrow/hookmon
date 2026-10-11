package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/dlenrow/hookmon/test/enrpki"
)

// robRunBus runs hookmon-bus's main with args and extra environment, and
// returns its exit code and output. It fails the test if the bus is still
// running after timeout.
func robRunBus(t *testing.T, timeout time.Duration, env []string, args ...string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], args...)
	cmd.Env = append(append(os.Environ(), secMainEnv+"=1"), env...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	start := time.Now()
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("hookmon-bus still running after %v; output:\n%s", time.Since(start), out.String())
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), out.String()
	}
	if err != nil {
		t.Fatal(err)
	}
	return 0, out.String()
}

// TestMain_EnrollTokenFileAndWrongCA: a bus enrolling with a token from
// --enroll-token-file (or $HOOKMON_ENROLL_TOKEN) against a server its
// --ca-file did not sign exits 1 at once, saying the server's certificate
// does not verify against the CA file. Before step 7f it retried for ever.
// The token never appears in the output.
func TestMain_EnrollTokenFileAndWrongCA(t *testing.T) {
	server, wrong := enrpki.New(t), enrpki.New(t)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(server.ServerTLS(t, tls.NoClientCert))))
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	dir := t.TempDir()
	const secret = "rob-token-0123456789abcdef0123456789abcdef"
	tokenFile := filepath.Join(dir, "enroll.token")
	if err := os.WriteFile(tokenFile, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "bus.yaml")
	cfg := fmt.Sprintf("status_port: 0\nstate_dir: %s\nfallback_log_path: %s\ntls:\n  server_name: localhost\n",
		filepath.Join(dir, "state"), filepath.Join(dir, "fallback.jsonl"))
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	base := []string{"--config", cfgPath, "--server-addr", "127.0.0.1:1", "--enroll-addr", lis.Addr().String(), "--ca-file", wrong.CACertFile}

	for name, run := range map[string]struct {
		args   []string
		env    []string
		source string
	}{
		"token file": {append(append([]string{}, base...), "--enroll-token-file", tokenFile), nil, "--enroll-token-file"},
		"token env":  {base, []string{"HOOKMON_ENROLL_TOKEN=" + secret}, "$HOOKMON_ENROLL_TOKEN"},
	} {
		start := time.Now()
		code, out := robRunBus(t, 30*time.Second, run.env, run.args...)
		if code != 1 {
			t.Errorf("%s: exit %d, want 1; output:\n%s", name, code, out)
		}
		if d := time.Since(start); d > 10*time.Second {
			t.Errorf("%s: took %v to fail", name, d)
		}
		for _, want := range []string{"does not verify against the CA file", "--ca-file", run.source} {
			if !strings.Contains(out, want) {
				t.Errorf("%s: output does not contain %q:\n%s", name, want, out)
			}
		}
		if strings.Contains(out, secret) {
			t.Errorf("%s: the token appears in the output:\n%s", name, out)
		}
		if strings.Contains(out, "sensor started") {
			t.Errorf("%s: sensors started before enrollment failed:\n%s", name, out)
		}
	}

	code, out := robRunBus(t, 30*time.Second, nil, append(append([]string{}, base...),
		"--enroll-token", secret, "--enroll-token-file", tokenFile)...)
	if code != 1 || !strings.Contains(out, "not both") {
		t.Errorf("both token flags: exit %d, output:\n%s", code, out)
	}
}
