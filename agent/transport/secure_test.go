package transport

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/dlenrow/hookmon/agent/config"
)

func secBusConfig(t *testing.T) *config.AgentConfig {
	t.Helper()
	dir := t.TempDir()
	return &config.AgentConfig{
		HostID:          "configured-id",
		ServerAddr:      "127.0.0.1:1",
		StateDir:        filepath.Join(dir, "state"),
		FallbackLogPath: filepath.Join(dir, "fallback.jsonl"),
	}
}

var secRetry = RetryConfig{InitialDelay: 10 * time.Millisecond, MaxDelay: 20 * time.Millisecond, Multiplier: 2, MaxAttempts: 1}

// TestEnsureIdentity_RefusesPlaintext: a bus with no certificate, no
// enrollment token and no --insecure must not connect at all. Before step
// 7b it logged a warning and connected in plaintext.
func TestEnsureIdentity_RefusesPlaintext(t *testing.T) {
	cfg := secBusConfig(t)
	err := EnsureIdentity(context.Background(), cfg, zap.NewNop(), secRetry)
	if !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("EnsureIdentity: got %v, want ErrNoIdentity", err)
	}
	if cfg.TLS.CertFile != "" || cfg.HostID != "configured-id" {
		t.Errorf("config changed on refusal: %+v", cfg)
	}

	noState := secBusConfig(t)
	noState.StateDir = ""
	if err := EnsureIdentity(context.Background(), noState, zap.NewNop(), secRetry); !errors.Is(err, ErrNoIdentity) {
		t.Errorf("EnsureIdentity without a state directory: got %v, want ErrNoIdentity", err)
	}

	for _, want := range []string{"--insecure", "--enroll-token", "tls.cert_file"} {
		if !strings.Contains(ErrNoIdentity.Error(), want) {
			t.Errorf("ErrNoIdentity does not mention %s: %q", want, ErrNoIdentity)
		}
	}
}

// TestEnsureIdentity_Insecure: with --insecure the bus needs no certificate
// and keeps its configured host ID.
func TestEnsureIdentity_Insecure(t *testing.T) {
	cfg := secBusConfig(t)
	cfg.TLS.Insecure = true
	if err := EnsureIdentity(context.Background(), cfg, zap.NewNop(), secRetry); err != nil {
		t.Fatalf("EnsureIdentity: %v", err)
	}
	if cfg.HostID != "configured-id" || cfg.TLS.CertFile != "" {
		t.Errorf("insecure config changed: %+v", cfg)
	}
}

// TestGRPCTransport_RefusesPlaintext: the transport itself returns
// ErrNoIdentity at once, without dialing, if it is run with no certificate
// and no --insecure.
func TestGRPCTransport_RefusesPlaintext(t *testing.T) {
	cfg := secBusConfig(t)
	tr := NewGRPCTransport(cfg, zap.NewNop(), secRetry)
	defer tr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	if err := tr.Run(ctx); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("Run: got %v, want ErrNoIdentity", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("Run took %v to refuse; it should not dial", d)
	}

	opts, err := (&GRPCTransport{cfg: cfg}).dialOptions()
	if err == nil {
		t.Errorf("dialOptions without a certificate or --insecure returned %d options and no error", len(opts))
	}
}
