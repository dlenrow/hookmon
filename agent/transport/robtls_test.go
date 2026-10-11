package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/dlenrow/hookmon/agent/config"
	hookmonv1 "github.com/dlenrow/hookmon/gen/hookmon/v1"
	hcrypto "github.com/dlenrow/hookmon/pkg/crypto"
	"github.com/dlenrow/hookmon/test/enrpki"
)

// robAgentService accepts event streams and refuses enrollment.
type robAgentService struct {
	hookmonv1.UnimplementedAgentServiceServer
}

func (robAgentService) StreamEvents(s hookmonv1.AgentService_StreamEventsServer) error {
	for {
		if _, err := s.Recv(); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

func (robAgentService) Enroll(context.Context, *hookmonv1.EnrollRequest) (*hookmonv1.EnrollResponse, error) {
	return nil, status.Error(codes.Unavailable, "try again")
}

// robTLSServer serves robAgentService on addr ("127.0.0.1:0" for any port)
// with pki's server certificate, requiring a client certificate when
// mutual is set. It returns the bound address and a stop func.
func robTLSServer(t *testing.T, pki *enrpki.PKI, addr string, mutual bool) (string, func()) {
	t.Helper()
	auth := tls.NoClientCert
	if mutual {
		auth = tls.RequireAndVerifyClientCert
	}
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(pki.ServerTLS(t, auth))))
	hookmonv1.RegisterAgentServiceServer(srv, robAgentService{})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String(), srv.Stop
}

// robIdentity writes a bus key and certificate from pki into dir and
// returns a config that uses them, with caFile as its CA.
func robIdentity(t *testing.T, pki *enrpki.PKI, serverAddr, caFile string) *config.AgentConfig {
	t.Helper()
	dir := t.TempDir()
	cert := pki.ClientCert(t, "8f0c3a52-1111-4222-8333-444455556666", hcrypto.HostCertOrganization)
	certPath, keyPath := filepath.Join(dir, "bus.crt"), filepath.Join(dir, "bus.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0o600); err != nil {
		t.Fatal(err)
	}
	keyDER, err := robMarshalKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return &config.AgentConfig{
		ServerAddr:      serverAddr,
		FallbackLogPath: filepath.Join(dir, "fallback.jsonl"),
		TLS:             config.TLSConfig{CertFile: certPath, KeyFile: keyPath, CAFile: caFile, ServerName: "localhost"},
	}
}

// robRetryForever retries without limit, quickly.
var robRetryForever = RetryConfig{InitialDelay: 10 * time.Millisecond, MaxDelay: 50 * time.Millisecond, Multiplier: 2}

// TestEnroll_WrongCAFailsFast: enrolling against a server whose
// certificate the --ca-file did not sign stops at once with
// ErrServerNotTrusted and a message naming --ca-file. Before step 7f the
// handshake failure was an Unavailable error, retried for ever.
func TestEnroll_WrongCAFailsFast(t *testing.T) {
	server, wrong := enrpki.New(t), enrpki.New(t)
	addr, _ := robTLSServer(t, server, "127.0.0.1:0", false)
	cfg := &config.AgentConfig{
		ServerAddr:      addr,
		EnrollAddr:      addr,
		StateDir:        filepath.Join(t.TempDir(), "state"),
		EnrollToken:     "token",
		FallbackLogPath: filepath.Join(t.TempDir(), "fallback.jsonl"),
		TLS:             config.TLSConfig{CAFile: wrong.CACertFile, ServerName: "localhost"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	start := time.Now()
	err := EnsureIdentity(ctx, cfg, zap.NewNop(), robRetryForever)
	if !errors.Is(err, ErrServerNotTrusted) {
		t.Fatalf("EnsureIdentity: %v after %v, want ErrServerNotTrusted", err, time.Since(start))
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %v to give up", d)
	}
	for _, want := range []string{"--ca-file", wrong.CACertFile, "certificate"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
	}
	t.Logf("enrollment with the wrong CA: %v", err)

	// The right CA gets past the handshake: the server's (transient)
	// refusal is retried, not reported as an untrusted server.
	cfg.TLS.CAFile = server.CACertFile
	cfg.StateDir = filepath.Join(t.TempDir(), "state")
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if err := EnsureIdentity(ctx2, cfg, zap.NewNop(), robRetryForever); errors.Is(err, ErrServerNotTrusted) || err == nil {
		t.Errorf("EnsureIdentity with the right CA: %v, want the retries to run until the deadline", err)
	}
}

// TestRun_WrongCAFailsFastOnFirstConnect: a bus whose CA file did not sign
// the server's certificate stops at its first connection with
// ErrServerNotTrusted, instead of retrying for ever. So does one that
// dials a name the server's certificate does not cover.
func TestRun_WrongCAFailsFastOnFirstConnect(t *testing.T) {
	server, wrong := enrpki.New(t), enrpki.New(t)
	addr, _ := robTLSServer(t, server, "127.0.0.1:0", true)

	for name, cfg := range map[string]*config.AgentConfig{
		"wrong CA":   robIdentity(t, server, addr, wrong.CACertFile),
		"wrong name": robIdentity(t, server, addr, server.CACertFile),
	} {
		if name == "wrong name" {
			cfg.TLS.ServerName = "not-the-server.example"
		}
		tr := NewGRPCTransport(cfg, zap.NewNop(), robRetryForever)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		start := time.Now()
		err := tr.Run(ctx)
		cancel()
		tr.Close()
		if !errors.Is(err, ErrServerNotTrusted) {
			t.Errorf("%s: Run returned %v after %v, want ErrServerNotTrusted", name, err, time.Since(start))
			continue
		}
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("%s: took %v to give up", name, d)
		}
		t.Logf("%s: %v", name, err)
	}

	// The right CA connects.
	cfg := robIdentity(t, server, addr, server.CACertFile)
	tr := NewGRPCTransport(cfg, zap.NewNop(), robRetryForever)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- tr.Run(ctx) }()
	deadline := time.Now().Add(10 * time.Second)
	for !tr.IsConnected() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !tr.IsConnected() {
		t.Error("the right CA did not connect")
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("Run after cancel: %v", err)
	}
	tr.Close()
}

// TestRun_UntrustedAfterConnectKeepsRetrying: once the bus has connected,
// a server that later presents a certificate the CA did not sign is
// retried (and logged) like any other failure, so a bus already running
// does not stop because of what answers at the server's address.
func TestRun_UntrustedAfterConnectKeepsRetrying(t *testing.T) {
	server, other := enrpki.New(t), enrpki.New(t)
	addr, stop := robTLSServer(t, server, "127.0.0.1:0", true)
	cfg := robIdentity(t, server, addr, server.CACertFile)
	tr := NewGRPCTransport(cfg, zap.NewNop(), robRetryForever)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- tr.Run(ctx) }()
	deadline := time.Now().Add(10 * time.Second)
	for !tr.IsConnected() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !tr.IsConnected() {
		t.Fatal("did not connect")
	}

	stop()
	robTLSServer(t, other, addr, false) // same address, a certificate the bus's CA did not sign
	select {
	case err := <-done:
		t.Fatalf("Run returned %v after a connected bus met an untrusted server; want it to keep retrying", err)
	case <-time.After(2 * time.Second):
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("Run after cancel: %v", err)
	}
	tr.Close()
}

func robMarshalKey(key any) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(key)
}
